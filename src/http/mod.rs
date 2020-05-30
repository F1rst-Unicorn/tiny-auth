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

use std::convert::From;

use crate::config::Web;
use crate::config::Crypto;
use crate::config::Tls;
use crate::store::memory::MemoryAuthorizationCodeStore;
use crate::store::memory::MemoryClientStore;
use crate::store::memory::MemoryUserStore;
use crate::systemd::notify_about_start;
use crate::systemd::notify_about_termination;
use crate::systemd::watchdog;
use crate::util::read_file;

use actix_web::cookie::SameSite;
use actix_web::dev::Server;
use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;

use actix_session::CookieSession;

use jsonwebtoken::EncodingKey;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Algorithm;

use openssl::ssl::SslAcceptorBuilder;
use openssl::ssl::SslFiletype;
use openssl::ssl::SslVerifyMode;
use openssl::x509::X509;
use openssl::x509::X509Name;
use openssl::x509::store::X509StoreBuilder;
use openssl::dh::Dh;

use log::debug;
use log::info;
use log::warn;
use log::error;

use tokio::signal::unix::signal;
use tokio::signal::unix::SignalKind;
use tokio::sync::oneshot;

#[derive(Debug)]
pub enum Error {
    StdIoError(std::io::Error),
    OpensslError(openssl::error::ErrorStack),
    JwtError(jsonwebtoken::errors::Error),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::StdIoError(error)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(error: openssl::error::ErrorStack) -> Self {
        Self::OpensslError(error)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::JwtError(error)
    }
}

pub fn run(web: Web, crypto: Crypto) -> Result<(), Error> {
    let mut tok_runtime = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .core_threads(4)
        .enable_all()
        .thread_name(env!("CARGO_PKG_NAME"))
        .build()?;

    let tasks = tokio::task::LocalSet::new();
    let system_fut = actix_rt::System::run_in_tokio(env!("CARGO_PKG_NAME"), &tasks);

    let (tx, rx) = oneshot::channel();

    tok_runtime.spawn(async move {
        let server = rx.await;

        if let Err(e) = server {
            return;
        }
        let server = server.unwrap();

        tokio::spawn(notify_about_start());
        tokio::spawn(watchdog());
        tokio::spawn(terminator(server));
    });

    tasks.block_on(&mut tok_runtime, async move {
        tokio::task::spawn_local(system_fut);
        let srv = configure_http_server(web, crypto);
        if srv.is_err() {
            return;
        }
        let srv = srv.unwrap();
        let result = tx.send(srv.clone());
        if result.is_err() {
            error!("Failed to create server");
            return;
        }
        if let Err(e) = srv.await {
            error!("HTTP server failed: {}", e);
        }
    });
    Ok(())
}

fn configure_http_server(web: Web, crypto: Crypto) -> Result<Server, Error> {
    let bind = web.bind.clone();
    let workers = web.workers;
    let tls = web.tls.clone();

    let tera = tera::load_template_engine(&web.static_files);

    let token_certificate = read_file(&crypto.public_key)?;
    let bytes = token_certificate.as_bytes();
    let mut decoding_key_result = DecodingKey::from_rsa_pem(bytes);
    if let Err(_) = decoding_key_result {
        decoding_key_result = DecodingKey::from_ec_pem(bytes);
        if let Err(e) = decoding_key_result {
            error!("failed to read public token key: {}", e);
            return Err(e.into());
        }
    }

    let file = read_file(&crypto.key)?;
    let bytes = file.as_bytes();
    let mut encoding_key_result = EncodingKey::from_rsa_pem(bytes);
    let mut ecdsa = false;
    if let Err(_) = encoding_key_result {
        encoding_key_result = EncodingKey::from_ec_pem(bytes);
        if let Err(e) = encoding_key_result {
            error!("failed to read private token key: {}", e);
            return Err(e.into());
        }
        ecdsa = true;
    }

    let algorithm = if ecdsa {
        Algorithm::ES384
    } else {
        Algorithm::PS512
    };

    let state = web::Data::new(state::State {
        instance: web.bind.to_string() + "/" + web.path.as_deref().unwrap_or(""),
        encoding_key: (encoding_key_result.unwrap(), algorithm),
        decoding_key: decoding_key_result.unwrap().into_static(),
        tera,
        client_store: Box::new(MemoryClientStore {}),
        user_store: Box::new(MemoryUserStore {}),
        auth_code_store: Box::new(MemoryAuthorizationCodeStore {}),
    });
    let server = HttpServer::new(move || {
        let token_certificate = token_certificate.clone();
        App::new()
            .app_data(state.clone())
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
                    .route("/cert", web::get().to(move || actix_web::HttpResponse::Ok().body(token_certificate.clone())))
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

async fn terminator(server: Server) -> Result<(), tokio::io::Error> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigquit = signal(SignalKind::quit())?;

    debug!("Signal handler ready");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sigquit.recv() => {}
    }

    info!("Exitting");
    tokio::spawn(notify_about_termination());
    tokio::select! {
        _ = server.stop(true) => {
            debug!("HTTP server stopped");
            return Ok(())
        }
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sigquit.recv() => {}
    };

    info!("Calm down, exitting immediately...");
    while tokio::select! {
        _ = server.stop(false) => {
            debug!("HTTP server stopped");
            return Ok(())
        }
        _ = sigint.recv() => {
            info!("Still waiting for shutdown...");
            true
        }
        _ = sigterm.recv() => {
            info!("Still waiting for shutdown...");
            true
        }
        _ = sigquit.recv() => {
            info!("Still waiting for shutdown...");
            true
        }
    } {}

    Ok(())
}
