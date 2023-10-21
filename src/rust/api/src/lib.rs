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

mod api;
mod auth;

use crate::api::TinyAuthApiImpl;
use crate::tiny_auth_proto::tiny_auth_api_server::TinyAuthApiServer;
use log::info;
use log::warn;
use tiny_auth_business::change_password::Handler;
use tokio::net::TcpListener;
use tokio::sync::oneshot::channel;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

pub(crate) mod tiny_auth_proto {
    // https://github.com/hyperium/tonic/issues/1056
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("api");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("tiny_auth_descriptor");
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error")]
    IoError(#[from] std::io::Error),
}

pub trait Constructor<'a> {
    fn endpoint(&self) -> &'a str;
    fn change_password_handler(&self) -> Handler;
}

pub async fn start(
    constructor: &impl Constructor<'_>,
) -> Result<(Sender<()>, JoinHandle<()>), Error> {
    let api = TinyAuthApiImpl {
        change_password: constructor.change_password_handler(),
    };
    let listener = TcpListener::bind(constructor.endpoint()).await?;
    let (tx, rx) = channel::<()>();

    let join_handle = tokio::spawn(async move {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(tiny_auth_proto::FILE_DESCRIPTOR_SET)
            .build()
            .unwrap();
        let server = Server::builder()
            .add_service(reflection_service)
            .add_service(TinyAuthApiServer::new(api))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                match rx.await {
                    Err(e) => warn!("terminating grpc api due to error: {}", e),
                    Ok(v) => {
                        info!("grpc api shutting down");
                        v
                    }
                }
            })
            .await;
        if let Err(e) = server {
            warn!("grpc api could not start: {}", e);
        }
    });

    Ok((tx, join_handle))
}
