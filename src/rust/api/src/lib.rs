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
use log::error;
use log::info;
use log::warn;
use tiny_auth_business::change_password::Handler;
use tokio::net::TcpListener;
use tokio::sync::oneshot::channel;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Certificate;
use tonic::transport::Identity;
use tonic::transport::Server;
use tonic::transport::ServerTlsConfig;

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
    #[error("grpc api error")]
    TonicError(#[from] tonic::transport::Error),
}

pub trait Constructor<'a> {
    fn endpoint(&self) -> &'a str;
    fn tls_key(&self) -> Option<String>;
    fn tls_cert(&self) -> Option<String>;
    fn tls_client_ca(&self) -> Option<String>;
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

    let identity = constructor
        .tls_cert()
        .zip(constructor.tls_key())
        .map(|(cert, key)| Identity::from_pem(cert, key));

    let client_ca = constructor.tls_client_ca().map(Certificate::from_pem);

    let mut server = Server::builder();
    if let Some(tls_config) = get_server_tls_config(identity, client_ca) {
        server = server.tls_config(tls_config)?;
    }

    let join_handle = tokio::spawn(async move {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(tiny_auth_proto::FILE_DESCRIPTOR_SET)
            .build()
            .unwrap();

        let server = server
            .accept_http1(true)
            .add_service(tonic_web::enable(reflection_service))
            .add_service(tonic_web::enable(TinyAuthApiServer::new(api)))
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

fn get_server_tls_config(
    identity: Option<Identity>,
    client_ca: Option<Certificate>,
) -> Option<ServerTlsConfig> {
    match identity {
        None => None,
        Some(identity) => {
            let mut result = ServerTlsConfig::new();
            result = result.identity(identity);
            if let Some(client_ca) = client_ca {
                result = result.client_ca_root(client_ca);
            }
            Some(result)
        }
    }
}
