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
use futures_util::future::FutureExt;
use std::pin::pin;
use tokio::io::Error;
use tokio::signal::unix::signal;
use tokio::signal::unix::SignalKind;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tracing::error;
use tracing::info;
use tracing::{debug, trace};

pub async fn terminator(
    server: ServerHandle,
    api_join_handle: (Sender<()>, JoinHandle<()>),
) -> Result<(), Error> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigquit = signal(SignalKind::quit())?;

    debug!("signal handler ready");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sigquit.recv() => {}
    }

    info!("exitting, waiting for connections to terminate gracefully");
    tokio::spawn(notify_about_termination());
    if api_join_handle.0.send(()).is_err() {
        error!("failed to terminate GRPC API");
    }
    let http_join_handle = tokio::spawn(server.stop(true));

    tokio::select! {
        _ = api_join_handle.1 => {
            debug!("GRPC server stopped");
        }
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sigquit.recv() => {}
    }

    tokio::select! {
        _ = http_join_handle => {
            debug!("HTTP server stopped");
            return Ok(())
        }
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sigquit.recv() => {}
    }

    let mut stop_server_immediately_future = pin!(tokio::spawn(server.stop(false)).fuse());
    trace!("waiting for immediate HTTP server shutdown");
    while tokio::select! {
        _ = &mut stop_server_immediately_future => {
            debug!("HTTP server stopped");
            false
        }
        _ = sigint.recv() => {
            true
        }
        _ = sigterm.recv() => {
            true
        }
        _ = sigquit.recv() => {
            true
        }
    } {
        info!("still waiting for shutdown...");
    }

    Ok(())
}
