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
use crate::logging::{FilterHandle, FormatHandle};
use crate::store::file::ReloadEvent;
use crate::systemd::notify_about_start;
use crate::systemd::watchdog;
use crate::terminate::terminator;
use crate::{config, logging};
use actix_web::dev::ServerHandle;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use openssl::error::ErrorStack;
use std::path::PathBuf;
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Receiver as MpscReceiver;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

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
    TemplateError(#[from] tiny_auth_business::template::TemplateError),

    #[error("Crypto error: {0}")]
    OpensslError(#[from] ErrorStack),

    #[error("Web error: {0}")]
    WebError(#[from] tiny_auth_web::Error),
}

pub fn run(
    config_path: &str,
    config: Config,
    handles: (FilterHandle, FormatHandle),
) -> Result<(), Error> {
    let tokio = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name(env!("CARGO_PKG_NAME"))
        .build()?;

    let actor_system = actix_rt::System::with_tokio_rt(|| tokio);
    actor_system.block_on(async move {
        let constructor = crate::constructor::Constructor::new(&config).await?;

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
        let reload_sender = constructor.reload_sender();
        let store_paths = constructor.store_paths();
        drop(constructor);
        tokio::spawn(config_refresher(
            config_path.to_owned(),
            config,
            handles,
            store_paths,
            reload_sender,
        ));
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

async fn config_refresher(
    config_path: String,
    mut config: Config,
    handles: (FilterHandle, FormatHandle),
    store_paths: Vec<PathBuf>,
    reload_sender: tokio::sync::broadcast::Sender<ReloadEvent>,
) {
    if !config.hot_reload {
        trace!(%config.hot_reload);
        return;
    }

    let (mut watcher, mut rx) = match async_watcher() {
        Err(e) => {
            warn!(%e, "watching config file failed");
            return;
        }
        Ok(v) => v,
    };

    let config_path_buf = PathBuf::from(config_path.clone());
    let config_parent = match config_path_buf.parent() {
        None => return,
        Some(v) => v,
    };
    if let Err(e) = watcher.watch(config_parent, RecursiveMode::Recursive) {
        warn!(%e, "watching config file failed");
        return;
    }
    for store_path in store_paths {
        if let Err(e) = watcher.watch(&store_path, RecursiveMode::Recursive) {
            warn!(%e, store_path = %store_path.display(), "watching failed");
            return;
        }
    }

    debug!("watching config file for changes");
    while let Some(res) = rx.recv().await {
        match res {
            Err(e) => warn!(%e, "failed to get new config file info"),
            Ok(event) => {
                if event.paths.iter().any(|v| v.ends_with(config_path.clone()))
                    && matches!(
                        event.kind,
                        EventKind::Any | EventKind::Modify(_) | EventKind::Other
                    )
                {
                    let new_config = match config::parser::parse_config_fallibly(&config_path) {
                        Err(e) => {
                            trace!(%e, "ignoring invalid config");
                            continue;
                        }
                        Ok(v) => v,
                    };
                    if new_config.log != config.log {
                        logging::reload_with_config(&new_config.log, &handles);
                    }
                    config = new_config;
                } else {
                    let event_to_send = if event.need_rescan() {
                        ReloadEvent::DirectoryChange
                    } else {
                        match event.kind {
                            EventKind::Create(_) => ReloadEvent::Add,
                            EventKind::Modify(_) => ReloadEvent::Modify,
                            EventKind::Remove(_) => ReloadEvent::Delete,
                            EventKind::Any | EventKind::Other => ReloadEvent::DirectoryChange,
                            EventKind::Access(_) => {
                                continue;
                            }
                        }
                    };
                    event.paths.iter().for_each(|v| {
                        if let Err(e) = reload_sender.send(event_to_send(v.to_owned())) {
                            warn!(%e, ?event.kind, "failed to apply file reload");
                        }
                    })
                }
            }
        }
    }
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, MpscReceiver<notify::Result<Event>>)> {
    let (tx, rx) = channel(1);

    let watcher = RecommendedWatcher::new(
        move |event| {
            trace!(hot_reload_event = ?event);
            if let Err(e) = tx.blocking_send(event) {
                warn!(%e, "failed to notify about config file change")
            }
        },
        notify::Config::default(),
    )?;

    Ok((watcher, rx))
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
