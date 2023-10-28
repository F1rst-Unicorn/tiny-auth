/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The tiny-auth developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

pub mod cors;
pub mod endpoints;
pub mod tera;

use crate::cors::cors_options_preflight;
use crate::cors::CorsChecker;
use crate::endpoints::cert::TokenCertificate;
use ::tera::Tera;
use actix_session::config::CookieContentSecurity;
use actix_session::config::PersistentSession;
use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::time::Duration;
use actix_web::cookie::{Key, SameSite};
use actix_web::dev::Server;
use actix_web::http::KeepAlive;
use actix_web::http::Method;
use actix_web::middleware::DefaultHeaders;
use actix_web::web::get;
use actix_web::web::method;
use actix_web::web::post;
use actix_web::web::route as all;
use actix_web::web::scope;
use actix_web::web::to;
use actix_web::web::Data;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;
use log::error;
use log::warn;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::server::ClientCertVerifier;
use rustls::server::NoClientAuth;
use rustls::Certificate;
use rustls::PrivateKey;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls_pemfile::certs;
use rustls_pemfile::pkcs8_private_keys;
use std::io::BufReader;
use std::sync::Arc;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_business::issuer_configuration::IssuerConfiguration;
use tiny_auth_business::jwk::Jwks;
use tiny_auth_business::store::AuthorizationCodeStore;
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::ScopeStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_business::token::TokenCreator;
use tiny_auth_business::token::TokenValidator;
use Error::LoggedBeforeError;

pub trait Constructor<'a> {
    fn get_template_engine(&self) -> Option<Tera>;
    fn get_public_key(&self) -> TokenCertificate;
    fn build_token_creator(&self) -> TokenCreator;
    fn token_validator(&self) -> Arc<TokenValidator>;
    fn user_store(&self) -> Arc<dyn UserStore>;
    fn get_client_store(&self) -> Option<Arc<dyn ClientStore>>;
    fn get_scope_store(&self) -> Option<Arc<dyn ScopeStore>>;
    fn build_auth_code_store(&self) -> Option<Arc<dyn AuthorizationCodeStore>>;
    fn authenticator(&self) -> Arc<Authenticator>;
    fn get_issuer_config(&self) -> IssuerConfiguration;
    fn build_jwks(&self) -> Jwks;
    fn build_cors_lister(&self) -> Arc<dyn CorsLister>;
    fn tls_key(&self) -> Option<String>;
    fn tls_cert(&self) -> Option<String>;
    fn tls_client_ca(&self) -> Option<String>;
    fn tls_versions(&self) -> Vec<&'static rustls::SupportedProtocolVersion>;
    fn bind(&self) -> String;
    fn workers(&self) -> Option<usize>;
    fn tls_enabled(&self) -> bool;
    fn web_path(&self) -> String;
    fn static_files(&self) -> String;
    fn session_timeout(&self) -> i64;
    fn session_same_site_policy(&self) -> SameSite;
    fn public_domain(&self) -> String;
    fn secret_key(&self) -> String;
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error: See above")]
    LoggedBeforeError,

    #[error("IO error")]
    StdIoError(#[from] std::io::Error),
}

pub fn build<'a>(constructor: &impl Constructor<'a>) -> Result<Server, Error> {
    let bind = constructor.bind();
    let workers = constructor.workers();

    let tera = constructor.get_template_engine().ok_or(LoggedBeforeError)?;
    let token_certificate = constructor.get_public_key();
    let token_creator = constructor.build_token_creator();
    let token_validator = constructor.token_validator();
    let user_store = constructor.user_store();
    let client_store = constructor.get_client_store().ok_or(LoggedBeforeError)?;
    let scope_store = constructor.get_scope_store().ok_or(LoggedBeforeError)?;
    let auth_code_store = constructor
        .build_auth_code_store()
        .ok_or(LoggedBeforeError)?;
    let authenticator = constructor.authenticator();
    let issuer_config = constructor.get_issuer_config();
    let jwks = constructor.build_jwks();
    let cors_lister = constructor.build_cors_lister();
    let cors_checker = Arc::new(CorsChecker::new(cors_lister.clone()));
    let user_info_handler =
        endpoints::userinfo::Handler::new(token_validator.clone(), cors_checker.clone());
    let token_handler = endpoints::token::Handler::new(
        Arc::new(tiny_auth_business::token_endpoint::Handler::new(
            client_store.clone(),
            user_store.clone(),
            auth_code_store.clone(),
            token_creator.clone(),
            authenticator.clone(),
            token_validator.clone(),
            scope_store.clone(),
            issuer_config.clone(),
        )),
        cors_checker,
    );

    let web_path = constructor.web_path();
    let static_files = constructor.static_files();
    let tls_enabled = constructor.tls_enabled();
    let session_timeout = constructor.session_timeout();
    let session_same_site_policy = constructor.session_same_site_policy();
    let public_domain = constructor.public_domain();
    let secret_key = constructor.secret_key();

    let server = HttpServer::new(move || {
        let token_certificate = token_certificate.clone();
        App::new()
            .app_data(Data::new(tera.clone()))
            .app_data(Data::from(authenticator.clone()))
            .app_data(Data::new(client_store.clone()))
            .app_data(Data::new(scope_store.clone()))
            .app_data(Data::new(user_store.clone()))
            .app_data(Data::new(auth_code_store.clone()))
            .app_data(Data::new(token_creator.clone()))
            .app_data(Data::new(token_validator.clone()))
            .app_data(Data::new(issuer_config.clone()))
            .app_data(Data::new(jwks.clone()))
            .app_data(Data::new(cors_lister.clone()))
            .app_data(Data::new(token_certificate))
            .app_data(Data::new(user_info_handler.clone()))
            .app_data(Data::new(token_handler.clone()))
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    Key::from(secret_key.as_bytes()),
                )
                .cookie_domain(Some(public_domain.clone()))
                .cookie_name("session".to_string())
                .cookie_path(web_path.clone())
                .cookie_secure(tls_enabled)
                .cookie_http_only(true)
                .cookie_same_site(session_same_site_policy)
                .session_lifecycle(
                    PersistentSession::default().session_ttl(Duration::seconds(session_timeout)),
                )
                .cookie_content_security(CookieContentSecurity::Private)
                .build(),
                // ^- encryption is only needed to avoid encoding problems
            )
            .wrap(DefaultHeaders::new().add(("Cache-Control", "no-store")))
            .wrap(DefaultHeaders::new().add(("Pragma", "no-cache")))
            .service(actix_files::Files::new(
                &(web_path.clone() + "/static/css"),
                static_files.clone() + "/css",
            ))
            .service(actix_files::Files::new(
                &(web_path.clone() + "/static/img"),
                static_files.clone() + "/img",
            ))
            .service(
                scope(&web_path)
                    .route(
                        "/.well-known/openid-configuration",
                        get().to(endpoints::discovery::get),
                    )
                    .route(
                        "/.well-known/openid-configuration",
                        method(Method::OPTIONS).to(cors_options_preflight),
                    )
                    .route(
                        "/.well-known/openid-configuration",
                        to(endpoints::method_not_allowed),
                    )
                    .route("/jwks", get().to(endpoints::discovery::jwks))
                    .route("/jwks", method(Method::OPTIONS).to(cors_options_preflight))
                    .route("/jwks", all().to(endpoints::method_not_allowed))
                    .route("/authorize", get().to(endpoints::authorize::handle))
                    .route("/authorize", post().to(endpoints::authorize::handle))
                    .route("/authorize", all().to(endpoints::method_not_allowed))
                    .route("/token", post().to(endpoints::token::post))
                    .route("/token", method(Method::OPTIONS).to(cors_options_preflight))
                    .route("/token", all().to(endpoints::method_not_allowed))
                    .route("/userinfo", get().to(endpoints::userinfo::get))
                    .route("/userinfo", post().to(endpoints::userinfo::post))
                    .route(
                        "/userinfo",
                        method(Method::OPTIONS).to(cors_options_preflight),
                    )
                    .route("/userinfo", all().to(endpoints::method_not_allowed))
                    .route("/authenticate", get().to(endpoints::authenticate::get))
                    .route("/authenticate", post().to(endpoints::authenticate::post))
                    .route("/authenticate", all().to(endpoints::method_not_allowed))
                    .route(
                        "/authenticate/cancel",
                        get().to(endpoints::authenticate::cancel),
                    )
                    .route(
                        "/authenticate/cancel",
                        all().to(endpoints::method_not_allowed),
                    )
                    .route(
                        "/select_account",
                        get().to(endpoints::authenticate::select_account),
                    )
                    .route("/select_account", all().to(endpoints::method_not_allowed))
                    .route("/consent", get().to(endpoints::consent::get))
                    .route("/consent", post().to(endpoints::consent::post))
                    .route("/consent", all().to(endpoints::method_not_allowed))
                    .route("/consent/cancel", get().to(endpoints::consent::cancel))
                    .route("/consent/cancel", all().to(endpoints::method_not_allowed))
                    .route("/cert", get().to(endpoints::cert::get))
                    .route("/cert", method(Method::OPTIONS).to(cors_options_preflight))
                    .route("/cert", all().to(endpoints::method_not_allowed))
                    .route("/health", get().to(endpoints::health::get))
                    .route(
                        "/health",
                        method(Method::OPTIONS).to(cors_options_preflight),
                    )
                    .route("/health", all().to(endpoints::method_not_allowed))
                    .route(
                        "/oidc-login-redirect-silent",
                        get().to(|| async { HttpResponse::NoContent().finish() }),
                    )
                    .route(
                        "/oidc-login-redirect-silent",
                        all().to(endpoints::method_not_allowed),
                    )
                    .route("/", get().to(endpoints::webapp_root::get))
                    .route("/", all().to(endpoints::method_not_allowed))
                    .route("/index.html", get().to(endpoints::webapp_root::get))
                    .route("/index.html", all().to(endpoints::method_not_allowed))
                    .service(actix_files::Files::new(
                        &(web_path.clone()),
                        static_files.clone() + "/js",
                    ))
                    .default_service(to(endpoints::webapp_root::get)),
            )
            .default_service(to(endpoints::webapp_root::get))
    })
    .disable_signals()
    .keep_alive(KeepAlive::Timeout(core::time::Duration::from_secs(60)))
    .shutdown_timeout(30);

    let server = if tls_enabled {
        let tls_config = configure_tls(constructor)?;
        server.bind_rustls(&bind, tls_config)
    } else {
        server.bind(&bind)
    };

    if let Err(e) = server {
        warn!("Failed to create server: {}", e);
        return Err(e.into());
    }
    let mut server = server.unwrap();

    if let Some(workers) = workers {
        server = server.workers(workers);
    }

    let srv = server.run();
    Ok(srv)
}

fn configure_tls<'a>(constructor: &impl Constructor<'a>) -> Result<ServerConfig, Error> {
    let client_cert_verifier = build_client_verifier(constructor)?;
    let server_certificate_chain = certs(&mut BufReader::new(
        constructor.tls_cert().expect("checked before").as_bytes(),
    ))?
    .into_iter()
    .map(Certificate)
    .collect();

    let key = match pkcs8_private_keys(&mut BufReader::new(
        constructor.tls_key().expect("checked before").as_bytes(),
    )) {
        Err(_) => {
            error!("could not read tls key file");
            return Err(LoggedBeforeError);
        }
        Ok(keys) => match keys.len() {
            0 => {
                error!("No tls key found");
                return Err(LoggedBeforeError);
            }
            1 => PrivateKey(keys[0].clone()),
            _ => {
                error!("Put only one tls key into the tls key file");
                return Err(LoggedBeforeError);
            }
        },
    };

    ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(constructor.tls_versions().as_slice())
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(server_certificate_chain, key)
        .map_err(|e| {
            error!("tls key is invalid: {}", e);
            LoggedBeforeError
        })
}

fn build_client_verifier<'a>(
    constructor: &impl Constructor<'a>,
) -> Result<Arc<dyn ClientCertVerifier>, Error> {
    let client_cert_verifier = if let Some(client_ca) = &constructor.tls_client_ca() {
        let mut ca_store = RootCertStore::empty();
        certs(&mut BufReader::new(client_ca.as_bytes()))?
            .into_iter()
            .map(Certificate)
            .map(|cert| ca_store.add(&cert))
            .enumerate()
            .filter(|(_, result)| result.is_err())
            .for_each(|(index, error)| {
                error!(
                    "ignoring client ca certificate at index {}: {}",
                    index,
                    error.unwrap_err()
                )
            });
        if ca_store.is_empty() {
            error!("No usable client ca certificates were found");
            return Err(LoggedBeforeError);
        }
        AllowAnyAuthenticatedClient::new(ca_store)
    } else {
        NoClientAuth::new()
    };
    Ok(client_cert_verifier)
}
