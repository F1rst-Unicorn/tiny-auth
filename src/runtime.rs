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

use log::error;

use rocket::Rocket;
use tokio::sync::oneshot;

use thiserror::Error;
use tokio::task::JoinHandle;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error. See above")]
    LoggedBeforeError,

    #[error("'web.secret key' needs at least 32 random characters")]
    SecretTooShort,

    #[error("IO error: {0}")]
    StdIoError(#[from] std::io::Error),

    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("Template error: {0}")]
    TeraError(#[from] tera::Error),

    #[error("Crypto error: {0}")]
    OpensslError(#[from] ErrorStack),

    #[error("'web.bind.address' is no valid IP address")]
    IpAddrParseError(#[from] std::net::AddrParseError),

    #[error("Interrupted")]
    JoinError(#[from] tokio::task::JoinError),

    #[error("HTTP failed to start")]
    RocketError(#[from] rocket::error::Error),
}

pub fn run(config: Config) -> Result<(), Error> {
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.web.workers.unwrap_or(4))
        .enable_all()
        .thread_name(env!("CARGO_PKG_NAME"))
        .build()?;

    let rocket: JoinHandle<Result<Rocket, Error>> = tokio_runtime.spawn(async move {
        let (rocket, shutdown) = http::build(config)?;

        tokio::spawn(notify_about_start());
        tokio::spawn(watchdog());
        tokio::spawn(terminator(shutdown));

        Ok(rocket)
    });

    let rocket = tokio_runtime.block_on(rocket)??;

    tokio_runtime.block_on(rocket.launch())?;

    Ok(())
}
