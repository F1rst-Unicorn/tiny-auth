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

use crate::tiny_auth_proto::password_change_response::HashedPassword;
use crate::tiny_auth_proto::tiny_auth_api_server::TinyAuthApi;
use crate::tiny_auth_proto::tiny_auth_api_server::TinyAuthApiServer;
use crate::tiny_auth_proto::HashedPasswordPbkdf2HmacSha256;
use crate::tiny_auth_proto::PasswordChangeRequest;
use crate::tiny_auth_proto::PasswordChangeResponse;
use async_trait::async_trait;
use log::info;
use log::warn;
use tokio::net::TcpListener;
use tokio::sync::oneshot::channel;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::Request;
use tonic::Response;

pub(crate) mod tiny_auth_proto {
    // https://github.com/hyperium/tonic/issues/1056
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("api");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("tiny_auth_descriptor");
}

#[derive(Default)]
struct TinyAuthApiImpl {}

#[async_trait]
impl TinyAuthApi for TinyAuthApiImpl {
    async fn change_password(
        &self,
        request: Request<PasswordChangeRequest>,
    ) -> Result<Response<PasswordChangeResponse>, tonic::Status> {
        info!(
            "User wants to change password to {}",
            request.into_inner().new_password
        );
        let response = PasswordChangeResponse {
            hashed_password: Some(HashedPassword::Pbkdf2HmacSha256(
                HashedPasswordPbkdf2HmacSha256 {
                    credential: "credential".to_string(),
                    iterations: 1409,
                    salt: "salt".to_string(),
                },
            )),
        };
        Ok(Response::new(response))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error")]
    IoError(#[from] std::io::Error),
}

pub async fn start(endpoint: &str) -> Result<(Sender<()>, JoinHandle<()>), Error> {
    let api = TinyAuthApiImpl::default();
    let listener = TcpListener::bind(endpoint).await?;
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
