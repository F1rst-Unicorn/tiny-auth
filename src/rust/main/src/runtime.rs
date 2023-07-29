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
use crate::http;
use crate::systemd::notify_about_start;
use crate::systemd::watchdog;
use crate::terminate::terminator;

use openssl::error::ErrorStack;

use actix_web::dev::ServerHandle;
use std::convert::From;
use std::fmt::Display;

use log::error;

use tokio::sync::oneshot;
use tokio::sync::oneshot::{Receiver, Sender};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub enum Error {
    LoggedBeforeError,

    StdIoError(std::io::Error),
    JwtError(jsonwebtoken::errors::Error),
    TeraError(tera::Error),
    OpensslError(ErrorStack),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoggedBeforeError => write!(f, "Error: See above"),
            Self::StdIoError(e) => write!(f, "IO error: {}", e),
            Self::JwtError(e) => write!(f, "JWT error: {}", e),
            Self::TeraError(e) => write!(f, "Template error: {}", e),
            Self::OpensslError(e) => write!(f, "Crypto error: {}", e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::StdIoError(error)
    }
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        Self::OpensslError(error)
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::JwtError(error)
    }
}

impl From<tera::Error> for Error {
    fn from(error: tera::Error) -> Self {
        Self::TeraError(error)
    }
}

pub fn run(config: Config) -> Result<(), Error> {
    let actor_system = actix_rt::System::with_tokio_rt(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name(env!("CARGO_PKG_NAME"))
            .build()
            .map_err(|e| {
                error!("failed to start tokio runtime: {}", e);
                e
            })
            .unwrap()
    });
    actor_system.block_on(async move {
        let (pass_server, receive_server) = oneshot::channel();
        let api_join_handle = match tiny_auth_api::start(&config.api.endpoint).await {
            Err(e) => {
                error!("GRPC API startup failed: {}", e);
                return;
            }
            Ok(v) => v,
        };
        tokio::spawn(runtime_primitives(receive_server, api_join_handle));

        let srv = match http::build(config) {
            Err(e) => {
                error!("Startup failed: {}", e);
                return;
            }
            Ok(srv) => srv,
        };
        if pass_server.send(srv.handle()).is_err() {
            error!("Failed to create server");
            return;
        }
        if let Err(e) = srv.await {
            error!("HTTP server failed: {}", e);
        }
    });
    Ok(())
}

async fn runtime_primitives(
    receive_server: Receiver<ServerHandle>,
    api_join_handle: (Sender<()>, JoinHandle<()>),
) {
    let server = match receive_server.await {
        Err(e) => {
            error!("failed to receive server: {}", e);
            return;
        }
        Ok(server) => server,
    };

    tokio::spawn(notify_about_start());
    tokio::spawn(watchdog());
    tokio::spawn(terminator(server, api_join_handle));
}
