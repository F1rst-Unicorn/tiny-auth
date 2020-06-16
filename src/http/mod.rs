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

use crate::business::authenticator::Authenticator;
use crate::business::token::TokenCreator;
use crate::config::Crypto;
use crate::config::Tls;
use crate::config::Web;
use crate::runtime::Error;
use crate::store::memory::MemoryAuthorizationCodeStore;
use crate::store::memory::MemoryClientStore;
use crate::store::memory::MemoryUserStore;
use crate::util::read_file;

use actix_web::cookie::SameSite;
use actix_web::dev::Server;
use actix_web::middleware::DefaultHeaders;
use actix_web::web;
use actix_web::App;
use actix_web::HttpResponse;
use actix_web::HttpServer;

use actix_session::CookieSession;

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;

use openssl::dh::Dh;
use openssl::ssl::SslAcceptorBuilder;
use openssl::ssl::SslFiletype;
use openssl::ssl::SslVerifyMode;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509Name;
use openssl::x509::X509;

use log::error;
use log::warn;

pub fn build(web: Web, crypto: Crypto) -> Result<Server, Error> {
    let bind = web.bind.clone();
    let workers = web.workers;
    let tls = web.tls.clone();

    let tera = tera::load_template_engine(&web.static_files);

    let token_certificate = read_file(&crypto.public_key)?;
    let bytes = token_certificate.as_bytes();
    let mut decoding_key_result = DecodingKey::from_rsa_pem(bytes);
    if decoding_key_result.is_err() {
        decoding_key_result = DecodingKey::from_ec_pem(bytes);
        if let Err(e) = decoding_key_result {
            error!("failed to read public token key: {}", e);
            return Err(e.into());
        }
    }

    let file = read_file(&crypto.key)?;
    let bytes = file.as_bytes();
    let mut encoding_key_result = EncodingKey::from_rsa_pem(bytes);
    let algorithm = if encoding_key_result.is_err() {
        encoding_key_result = EncodingKey::from_ec_pem(bytes);
        if let Err(e) = encoding_key_result {
            error!("failed to read private token key: {}", e);
            return Err(e.into());
        }
        Algorithm::ES384
    } else {
        Algorithm::PS512
    };

    let encoding_key = encoding_key_result.unwrap();
    let token_issuer = web.bind.to_string() + "/" + web.path.as_deref().unwrap_or("");

    let token_creator = TokenCreator::new(encoding_key, algorithm, token_issuer);

    let server = HttpServer::new(move || {
        let token_certificate = token_certificate.clone();
        App::new()
            .app_data(tera.clone())
            .app_data(web::Data::new(Authenticator::new(Box::new(
                MemoryUserStore {},
            ))))
            .app_data(web::Data::new(Box::new(MemoryClientStore {})))
            .app_data(web::Data::new(Box::new(MemoryAuthorizationCodeStore {})))
            .app_data(web::Data::new(token_creator.clone()))
            .wrap(
                CookieSession::private(web.secret_key.as_bytes())
                    // ^- encryption is only needed to avoid encoding problems
                    .domain(&web.domain)
                    .name("session")
                    .path(web.path.as_ref().expect("no default given"))
                    .secure(web.tls.is_some())
                    .http_only(true)
                    .same_site(SameSite::Strict)
                    .max_age(web.session_timeout.expect("no default given")),
            )
            .wrap(DefaultHeaders::new().header("Cache-Control", "no-store"))
            .service(
                web::scope(&web.path.as_ref().expect("no default given"))
                    .route("/authorize", web::get().to(endpoints::authorize::get))
                    .route("/authorize", web::post().to(endpoints::authorize::post))
                    .route("/token", web::post().to(endpoints::token::post))
                    .route("/userinfo", web::get().to(endpoints::userinfo::get))
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
