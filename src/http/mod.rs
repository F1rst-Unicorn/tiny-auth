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
mod state;
mod tera;

use crate::config::Config;
use crate::config::Tls;
use crate::runtime::Error;
use crate::util::read_file;

use actix_web::cookie::SameSite;
use actix_web::dev::Server;
use actix_web::middleware::DefaultHeaders;
use actix_web::web;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;

use actix_session::CookieSession;

use openssl::dh::Dh;
use openssl::ssl::SslAcceptorBuilder;
use openssl::ssl::SslFiletype;
use openssl::ssl::SslVerifyMode;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509Name;
use openssl::x509::X509;

use log::error;
use log::warn;

pub fn build(config: Config) -> Result<Server, Error> {
    let bind = config.web.bind.clone();
    let workers = config.web.workers;
    let tls = config.web.tls.clone();

    let constructor = state::Constructor::new(&config);

    let tera = constructor.build_template_engine()?;
    let token_certificate = constructor.build_public_key()?;
    let token_creator = constructor.build_token_creator()?;
    let token_validator = constructor.build_token_validator()?;
    let user_store = constructor
        .build_user_store()
        .ok_or(Error::LoggedBeforeError)?;
    let client_store = constructor
        .build_client_store()
        .ok_or(Error::LoggedBeforeError)?;
    let auth_code_store = constructor
        .build_auth_code_store()
        .ok_or(Error::LoggedBeforeError)?;
    let authenticator = constructor
        .build_authenticator()
        .ok_or(Error::LoggedBeforeError)?;

    let server = HttpServer::new(move || {
        let token_certificate = token_certificate.clone();
        App::new()
            .app_data(web::Data::new(tera.clone()))
            .app_data(web::Data::new(authenticator.clone()))
            .app_data(web::Data::new(client_store.clone()))
            .app_data(web::Data::new(user_store.clone()))
            .app_data(web::Data::new(auth_code_store.clone()))
            .app_data(web::Data::new(token_creator.clone()))
            .app_data(web::Data::new(token_validator.clone()))
            .wrap(
                CookieSession::private(config.web.secret_key.as_bytes())
                    // ^- encryption is only needed to avoid encoding problems
                    .domain(&config.web.domain)
                    .name("session")
                    .path(config.web.path.as_ref().expect("no default given"))
                    .secure(config.web.tls.is_some())
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .max_age(config.web.session_timeout.expect("no default given")),
            )
            .wrap(DefaultHeaders::new().header("Cache-Control", "no-store"))
            .service(
                web::scope(&config.web.path.as_ref().expect("no default given"))
                    .route("/authorize", web::get().to(endpoints::authorize::get))
                    .route("/authorize", web::post().to(endpoints::authorize::post))
                    .route("/token", web::post().to(endpoints::token::post))
                    .route("/userinfo", web::get().to(endpoints::userinfo::handle))
                    .route("/userinfo", web::post().to(endpoints::userinfo::handle))
                    .route("/authenticate", web::get().to(endpoints::authenticate::get))
                    .route(
                        "/authenticate",
                        web::post().to(endpoints::authenticate::post),
                    )
                    .route("/consent", web::get().to(endpoints::consent::get))
                    .route("/consent", web::post().to(endpoints::consent::post))
                    .route(
                        "/cert",
                        web::get().to(move || HttpResponse::Ok().body(token_certificate.clone())),
                    ),
            )
    })
    .disable_signals()
    .shutdown_timeout(30);

    let server = if let Some(tls) = tls {
        let openssl = configure_openssl(&tls);
        if let Err(e) = openssl {
            return Err(e);
        }
        server.bind_openssl(&bind, openssl.unwrap())
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

fn configure_openssl(config: &Tls) -> Result<SslAcceptorBuilder, Error> {
    let mut builder = config.configuration.to_acceptor_builder()?;

    if let Some(client_ca) = &config.client_ca {
        let mut mode = SslVerifyMode::empty();
        mode.insert(SslVerifyMode::PEER);
        mode.insert(SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        builder.set_verify(mode);
        builder.set_verify_depth(30);
        builder.set_client_ca_list(X509Name::load_client_ca_file(client_ca)?);

        let cert_content = read_file(client_ca);
        if let Err(e) = cert_content {
            return Err(e.into());
        }
        let cert = X509::from_pem(cert_content.unwrap().as_bytes())?;
        let mut store_builder = X509StoreBuilder::new()?;
        store_builder.add_cert(cert)?;
        let store = store_builder.build();
        builder.set_verify_cert_store(store)?;
    } else {
        builder.set_verify(SslVerifyMode::NONE);
    }

    if let Some(ciphers) = &config.old_ciphers {
        builder.set_cipher_list(&ciphers)?;
    }

    if let Some(ciphers) = &config.ciphers {
        builder.set_ciphersuites(&ciphers)?;
    }

    if let Some(dhparam) = &config.dh_param {
        let content = read_file(dhparam);
        if let Err(e) = content {
            error!("Could not open {}: {}", dhparam, e);
            return Err(e.into());
        }
        let dhparam = Dh::params_from_pem(content.unwrap().as_bytes())?;
        builder.set_tmp_dh(&dhparam)?;
    }

    builder.set_private_key_file(&config.key, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(&config.certificate)?;

    Ok(builder)
}
