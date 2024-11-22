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
use crate::auth::AUTHORIZATION_HEADER_KEY;
use crate::tiny_auth_proto::tiny_auth_api_server::TinyAuthApiServer;
use http::uri::PathAndQuery;
use http::{HeaderName, Request, Response, Uri};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;
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
use tower::{Layer, Service};
use tower_http::cors::AllowOrigin;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing::warn;
use tracing::{error, instrument, trace};

pub(crate) mod tiny_auth_proto {
    // https://github.com/hyperium/tonic/issues/1056
    #![allow(clippy::derive_partial_eq_without_eq)]
    #![allow(clippy::unwrap_used)]
    tonic::include_proto!("api");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("tiny_auth_descriptor");
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("grpc api error: {0}")]
    TonicError(#[from] tonic::transport::Error),
    #[error("grpc reflection error: {0}")]
    TonicReflectionError(#[from] tonic_reflection::server::Error),
}

pub trait Constructor<'a> {
    fn endpoint(&self) -> &'a str;
    fn path(&self) -> &'a str;
    fn tls_key(&self) -> Option<String>;
    fn tls_cert(&self) -> Option<String>;
    fn tls_client_ca(&self) -> Option<String>;
    fn change_password_handler(&self) -> Handler;
}

const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const DEFAULT_EXPOSED_HEADERS: [&str; 3] =
    ["grpc-status", "grpc-message", "grpc-status-details-bin"];
const DEFAULT_ALLOW_HEADERS: [&str; 5] = [
    "x-grpc-web",
    "content-type",
    "x-user-agent",
    "grpc-timeout",
    AUTHORIZATION_HEADER_KEY,
];

#[instrument(name = "grpc_start", skip_all)]
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
        trace!("tls enabled")
    }

    let path_prefix = constructor.path().to_string();

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(tiny_auth_proto::FILE_DESCRIPTOR_SET)
        .build()?;

    let join_handle = tokio::spawn(async move {
        let server = server
            .accept_http1(true)
            .layer(RerouteLayer { path_prefix })
            .layer(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::mirror_request())
                    .allow_credentials(true)
                    .max_age(DEFAULT_MAX_AGE)
                    .expose_headers(
                        DEFAULT_EXPOSED_HEADERS
                            .iter()
                            .cloned()
                            .map(HeaderName::from_static)
                            .collect::<Vec<HeaderName>>(),
                    )
                    .allow_headers(
                        DEFAULT_ALLOW_HEADERS
                            .iter()
                            .cloned()
                            .map(HeaderName::from_static)
                            .collect::<Vec<HeaderName>>(),
                    ),
            )
            .add_service(tonic_web::enable(reflection_service))
            .add_service(tonic_web::enable(TinyAuthApiServer::new(api)))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                match rx.await {
                    Err(e) => warn!(%e, "terminating due to error"),
                    Ok(v) => {
                        info!("shutting down");
                        v
                    }
                }
            })
            .await;
        if let Err(e) = server {
            warn!(%e, "could not start");
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

#[derive(Clone)]
pub struct RerouteLayer {
    path_prefix: String,
}

impl<S> Layer<S> for RerouteLayer {
    type Service = RerouteService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RerouteService {
            inner,
            path_prefix: self.path_prefix.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RerouteService<S> {
    inner: S,
    path_prefix: String,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RerouteService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let (mut parts, body) = request.into_parts();
        parts.uri = rewrite_uri(parts.uri, &self.path_prefix);
        let req = Request::from_parts(parts, body);
        ResponseFuture {
            inner: self.inner.call(req),
        }
    }
}

pin_project! {
    pub struct ResponseFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F, B, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Default,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(ready!(self.project().inner.poll(cx))?))
    }
}

fn rewrite_uri(uri: Uri, path_prefix: &str) -> Uri {
    let mut builder = Uri::builder();
    if let Some(scheme) = uri.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    if let Some(authority) = uri.authority() {
        builder = builder.authority(authority.clone());
    }
    if let Some(path_and_query) = uri.path_and_query() {
        builder = builder.path_and_query(rewrite_path(path_and_query, path_prefix));
    }
    builder
        .build()
        .inspect_err(|e| error!(%e, %uri, %path_prefix, "rewriting url failed"))
        .unwrap_or(uri)
}

fn rewrite_path(path_and_query: &PathAndQuery, path_prefix: &str) -> PathAndQuery {
    path_and_query
        .path()
        .strip_prefix(path_prefix)
        .map(|v| v.to_string() + path_and_query.query().unwrap_or(""))
        .map(PathAndQuery::try_from)
        .and_then(Result::ok)
        .unwrap_or(path_and_query.clone())
}
