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

use crate::config::Config;
use crate::systemd::notify_about_start;
use crate::systemd::watchdog;
use crate::terminate::terminator;
use actix_web::dev::ServerHandle;
use openssl::error::ErrorStack;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tracing::error;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error: See above")]
    LoggedBeforeError,

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("IO error: {0}")]
    StdIoError(#[from] std::io::Error),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Template error: {0}")]
    TeraError(#[from] tera::Error),

    #[error("Crypto error: {0}")]
    OpensslError(#[from] ErrorStack),

    #[error("Web error: {0}")]
    WebError(#[from] tiny_auth_web::Error),
}

pub fn run(config: Config) -> Result<(), Error> {
    let actor_system = actix_rt::System::with_tokio_rt(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name(env!("CARGO_PKG_NAME"))
            .build()
            .map_err(|e| {
                error!(%e, "failed to start tokio runtime");
                e
            })
            .unwrap()
    });
    actor_system.block_on(async move {
        let constructor = crate::constructor::Constructor::new(&config)?;

        let (pass_server, receive_server) = oneshot::channel();
        let api_join_handle = match tiny_auth_api::start(&constructor).await {
            Err(e) => {
                error!(%e, "GRPC API startup failed");
                return Ok::<(), Error>(());
            }
            Ok(v) => v,
        };
        tokio::spawn(runtime_primitives(receive_server, api_join_handle));

        let srv = match tiny_auth_web::build(&constructor) {
            Err(e) => {
                error!(%e, "startup failed");
                return Ok(());
            }
            Ok(srv) => srv,
        };
        drop(constructor);
        if pass_server.send(srv.handle()).is_err() {
            error!("failed to create server");
            return Ok(());
        }
        if let Err(e) = srv.await {
            error!(%e, "HTTP server failed");
        }

        Ok(())
    })?;
    Ok(())
}

async fn runtime_primitives(
    receive_server: Receiver<ServerHandle>,
    api_join_handle: (Sender<()>, JoinHandle<()>),
) {
    let server = match receive_server.await {
        Err(e) => {
            error!(%e, "failed to receive server");
            return;
        }
        Ok(server) => server,
    };

    tokio::spawn(notify_about_start());
    tokio::spawn(watchdog());
    tokio::spawn(terminator(server, api_join_handle));
}
