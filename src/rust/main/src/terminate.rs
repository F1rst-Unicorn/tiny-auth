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

use crate::systemd::notify_about_termination;
use actix_web::dev::ServerHandle;
use log::debug;
use log::info;
use tokio::io::Error;
use tokio::signal::unix::signal;
use tokio::signal::unix::SignalKind;

#[allow(clippy::cognitive_complexity)] // not really complex to read
pub async fn terminator(server: ServerHandle) -> Result<(), Error> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigquit = signal(SignalKind::quit())?;

    debug!("Signal handler ready");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sigquit.recv() => {}
    }

    info!("Exitting, waiting 30s for connections to terminate");
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

    info!("Calm down...");
    while tokio::select! {
        _ = server.stop(false) => {
            debug!("HTTP server stopped");
            false
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
