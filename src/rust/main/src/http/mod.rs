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

pub mod endpoints;
pub mod state;
mod tera;

use crate::config::Config;
use crate::config::Tls;
use crate::config::TlsVersion;
use crate::runtime::Error;
use tiny_auth_web::cors::cors_options_preflight;

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use actix_web::cookie::SameSite;
use actix_web::dev::Server;
use actix_web::http::Method;
use actix_web::middleware::DefaultHeaders;
use actix_web::web::get;
use actix_web::web::method;
use actix_web::web::post;
use actix_web::web::route as all;
use actix_web::web::scope;
use actix_web::web::Data;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;

use actix_session::CookieSession;

use rustls::internal::pemfile::certs;
use rustls::internal::pemfile::pkcs8_private_keys;
use rustls::AllowAnyAuthenticatedClient;
use rustls::NoClientAuth;
use rustls::RootCertStore;
use rustls::ServerConfig;

use crate::store::Store;
use log::error;
use log::warn;

#[derive(Clone)]
pub struct TokenCertificate(String);

pub fn build(config: Config) -> Result<Server, Error> {
    let bind = config.web.bind.clone();
    let workers = config.web.workers;
    let tls = config.web.tls.clone();

    let constructor = state::Constructor::new(&config)?;

    let tera = constructor
        .get_template_engine()
        .ok_or(Error::LoggedBeforeError)?;
    let token_certificate = constructor.get_public_key();
    let token_creator = constructor.build_token_creator()?;
    let token_validator = constructor.build_token_validator()?;
    let user_store = constructor
        .get_user_store()
        .ok_or(Error::LoggedBeforeError)?;
    let client_store = constructor
        .get_client_store()
        .ok_or(Error::LoggedBeforeError)?;
    let scope_store = constructor
        .get_scope_store()
        .ok_or(Error::LoggedBeforeError)?;
    let auth_code_store = constructor
        .build_auth_code_store()
        .ok_or(Error::LoggedBeforeError)?;
    let authenticator = constructor
        .build_authenticator()
        .ok_or(Error::LoggedBeforeError)?;
    let issuer_config = constructor.get_issuer_config();
    let jwks = constructor.build_jwks()?;
    let cors_lister = constructor.build_cors_lister()?;
    let unified_store = Arc::new(Store {
        user_store: user_store.clone(),
        client_store: client_store.clone(),
        scope_store: scope_store.clone(),
        auth_code_store: auth_code_store.clone(),
    });

    std::mem::drop(constructor);

    let server = HttpServer::new(move || {
        let token_certificate = token_certificate.clone();
        App::new()
            .app_data(Data::new(tera.clone()))
            .app_data(Data::new(authenticator.clone()))
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
            .app_data(Data::new(unified_store.clone()))
            .wrap(
                CookieSession::private(config.web.secret_key.as_bytes())
                    // ^- encryption is only needed to avoid encoding problems
                    .domain(&config.web.public_host.domain)
                    .name("session")
                    .path(config.web.path.as_ref().expect("no default given"))
                    .secure(config.web.tls.is_some())
                    .http_only(true)
                    .same_site(SameSite::Lax)
                    .max_age(config.web.session_timeout.expect("no default given")),
            )
            .wrap(DefaultHeaders::new().header("Cache-Control", "no-store"))
            .wrap(DefaultHeaders::new().header("Pragma", "no-cache"))
            .service(actix_files::Files::new(
                &(config.web.path.clone().unwrap() + "/static/css"),
                config.web.static_files.clone() + "/css",
            ))
            .service(actix_files::Files::new(
                &(config.web.path.clone().unwrap() + "/static/img"),
                config.web.static_files.clone() + "/img",
            ))
            .service(
                scope(config.web.path.as_ref().unwrap())
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
                        all().to(endpoints::method_not_allowed),
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
                    .default_service(all().to(|| HttpResponse::NotFound().body("not found"))),
            )
    })
    .disable_signals()
    .keep_alive(60)
    .shutdown_timeout(30);

    let server = if let Some(tls) = tls {
        let tls_config = configure_tls(&tls)?;
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

fn configure_tls(config: &Tls) -> Result<ServerConfig, Error> {
    let mut result = if let Some(client_ca) = &config.client_ca {
        let mut ca_store = RootCertStore::empty();
        if ca_store
            .add_pem_file(&mut BufReader::new(File::open(client_ca)?))
            .is_err()
        {
            error!("could not load tls client ca");
            return Err(Error::LoggedBeforeError);
        }
        ServerConfig::new(AllowAnyAuthenticatedClient::new(ca_store))
    } else {
        ServerConfig::new(NoClientAuth::new())
    };

    let certs = match certs(&mut BufReader::new(File::open(&config.certificate)?)) {
        Err(_) => {
            error!("could not read tls certificate file");
            return Err(Error::LoggedBeforeError);
        }
        Ok(certs) => certs,
    };

    let key = match pkcs8_private_keys(&mut BufReader::new(File::open(&config.key)?)) {
        Err(_) => {
            error!("could not read tls key file");
            return Err(Error::LoggedBeforeError);
        }
        Ok(keys) => match keys.len() {
            0 => {
                error!("No tls key found");
                return Err(Error::LoggedBeforeError);
            }
            1 => keys[0].clone(),
            _ => {
                error!("Put only one tls key into the tls key file");
                return Err(Error::LoggedBeforeError);
            }
        },
    };

    if let Err(e) = result.set_single_cert(certs, key) {
        error!("tls key is invalid: {}", e);
        return Err(Error::LoggedBeforeError);
    }

    result.versions = config
        .versions
        .clone()
        .into_iter()
        .map(TlsVersion::into)
        .collect();

    Ok(result)
}
