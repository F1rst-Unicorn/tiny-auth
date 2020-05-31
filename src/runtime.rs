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

use std::convert::From;

use crate::config::Crypto;
use crate::config::Web;
use crate::http;
use crate::systemd::notify_about_start;
use crate::systemd::watchdog;
use crate::terminate::terminator;

use log::error;

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

    let (pass_server, receive_server) = oneshot::channel();

    tok_runtime.spawn(async move {
        let server = receive_server.await;

        if let Err(e) = server {
            error!("failed to receive server: {}", e);
            return;
        }
        let server = server.unwrap();

        tokio::spawn(notify_about_start());
        tokio::spawn(watchdog());
        tokio::spawn(terminator(server));
    });

    let tasks = tokio::task::LocalSet::new();
    let system_fut = actix_rt::System::run_in_tokio(env!("CARGO_PKG_NAME"), &tasks);

    tasks.block_on(&mut tok_runtime, async move {
        tokio::task::spawn_local(system_fut);
        let srv = http::build(web, crypto);
        if srv.is_err() {
            return;
        }
        let srv = srv.unwrap();
        let result = pass_server.send(srv.clone());
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
