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

use actix_web::cookie::SameSite;
use actix_web::dev::Server;
use actix_web::web;
use actix_web::App;
use actix_web::HttpServer;

use actix_session::CookieSession;

use crate::config;
use crate::store::memory::MemoryAuthorizationCodeStore;
use crate::store::memory::MemoryClientStore;
use crate::store::memory::MemoryUserStore;
use crate::systemd::notify_about_start;
use crate::systemd::notify_about_termination;
use crate::systemd::watchdog;

use log::debug;
use log::info;
use log::warn;

use tokio::signal::unix::signal;
use tokio::signal::unix::SignalKind;
use tokio::sync::oneshot;

pub fn run(web: config::Web) -> std::io::Result<()> {
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
            warn!("Failed to create server: {}", e);
            return;
        }
        let server = server.unwrap();

        tokio::spawn(notify_about_start());
        tokio::spawn(watchdog());
        tokio::spawn(terminator(server));
    });

    tasks.block_on(&mut tok_runtime, async move {
        tokio::task::spawn_local(system_fut);
        let bind = web.bind.clone();
        let workers = web.workers;

        let tera = tera::load_template_engine(&web.static_files);

        let state = web::Data::new(state::State {
            tera,
            client_store: Box::new(MemoryClientStore {}),
            user_store: Box::new(MemoryUserStore {}),
            auth_code_store: Box::new(MemoryAuthorizationCodeStore {}),
        });
        let server = HttpServer::new(move || {
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
                        .route("/consent", web::post().to(endpoints::consent::post)),
                )
        })
        .disable_signals()
        .shutdown_timeout(30)
        .bind(&bind);

        if let Err(e) = server {
            warn!("Failed to create server: {}", e);
            return;
        }
        let mut server = server.unwrap();

        if let Some(workers) = workers {
            server = server.workers(workers);
        }

        let srv = server.run();
        let result = tx.send(srv.clone());
        if result.is_err() {
            warn!("Failed to create server");
            return;
        }
        if let Err(e) = srv.await {
            warn!("HTTP server failed: {}", e);
        }
    });
    Ok(())
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
