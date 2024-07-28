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

use super::parse_bearer_authorization;
use crate::cors::render_invalid_request;
use crate::cors::CorsCheckResult;
use crate::cors::CorsChecker;
use actix_web::web::Data;
use actix_web::web::Form;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use serde_derive::Deserialize;
use std::sync::Arc;
use thiserror::Error;
use tiny_auth_business::token::Token;
use tiny_auth_business::token::{EncodedAccessToken, Userinfo};
use tiny_auth_business::userinfo_endpoint;
use tiny_auth_business::userinfo_endpoint::Handler as BusinessHandler;
use tiny_auth_business::userinfo_endpoint::Request as BusinessRequest;
use tracing::{debug, instrument};

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    access_token: Option<EncodedAccessToken>,
}

#[instrument(skip_all, name = "userinfo_get")]
pub async fn get(request: HttpRequest, handler: Data<Handler>) -> HttpResponse {
    post(Form(Request { access_token: None }), request, handler).await
}

#[instrument(skip_all, name = "userinfo_post")]
pub async fn post(
    query: Form<Request>,
    request: HttpRequest,
    handler: Data<Handler>,
) -> HttpResponse {
    let cors_check_result = handler.check_cors(&request);
    if let CorsCheckResult::IllegalOrigin = cors_check_result {
        return render_invalid_request();
    }

    match handler.handle(query, &request).await {
        Ok(token) => cors_check_result
            .with_headers(HttpResponse::Ok())
            .json(token),
        Err(Error::InvalidAuthorizationHeader) => cors_check_result
            .with_headers(HttpResponse::Unauthorized())
            .append_header((
                "www-authenticate",
                "error=\"invalid_request\", error_description=\"Invalid authorization header\"",
            ))
            .finish(),
        Err(Error::MissingAuthorizationHeader) => cors_check_result
            .with_headers(HttpResponse::BadRequest())
            .append_header((
                "www-authenticate",
                "error=\"invalid_request\", error_description=\"Missing authorization header\"",
            ))
            .finish(),
        Err(Error::BusinessError(e)) => cors_check_result
            .with_headers(HttpResponse::Unauthorized())
            .append_header((
                "www-authenticate",
                format!("error=\"invalid_token\", error_description=\"{}\"", e),
            ))
            .finish(),
    }
}

#[derive(Clone)]
pub struct Handler {
    handler: Arc<BusinessHandler>,
    cors_checker: Arc<CorsChecker>,
}

impl Handler {
    fn check_cors<'a>(&self, request: &'a HttpRequest) -> CorsCheckResult<'a> {
        self.cors_checker.check(request)
    }

    async fn handle(
        &self,
        query: Form<Request>,
        request: &HttpRequest,
    ) -> Result<Token<Userinfo>, Error> {
        let token = Self::look_up_token(query, request)?;

        Ok(self.handler.get_userinfo(BusinessRequest { token }).await?)
    }

    fn look_up_token(
        query: Form<Request>,
        request: &HttpRequest,
    ) -> Result<EncodedAccessToken, Error> {
        if let Some(token) = &query.access_token {
            Ok(token.clone())
        } else {
            match request.headers().get("Authorization") {
                Some(header) => match parse_bearer_authorization(header) {
                    Some(token) => {
                        match serde_json::from_str::<EncodedAccessToken>(&format!("\"{}\"", &token))
                        {
                            Err(e) => {
                                debug!(%e, "invalid authorization header");
                                Err(Error::InvalidAuthorizationHeader)
                            }
                            Ok(v) => Ok(v),
                        }
                    }
                    None => {
                        debug!("invalid authorization header");
                        Err(Error::InvalidAuthorizationHeader)
                    }
                },
                None => {
                    debug!("missing authorization header");
                    Err(Error::MissingAuthorizationHeader)
                }
            }
        }
    }
}

pub mod inject {
    use super::Handler;
    use crate::cors::CorsChecker;
    use std::sync::Arc;
    use tiny_auth_business::userinfo_endpoint::Handler as BusinessHandler;

    pub fn handler(handler: Arc<BusinessHandler>, cors_checker: Arc<CorsChecker>) -> Handler {
        Handler {
            handler,
            cors_checker,
        }
    }
}

#[derive(Debug, Error)]
enum Error {
    #[error("invalid authorization header")]
    InvalidAuthorizationHeader,
    #[error("missing authorization header")]
    MissingAuthorizationHeader,
    #[error("{0}")]
    BusinessError(#[from] userinfo_endpoint::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::tests::read_response;
    use actix_web::http;
    use actix_web::test;
    use tiny_auth_business::cors::test_fixtures::cors_lister;
    use tiny_auth_business::store::test_fixtures::build_test_client_store;
    use tiny_auth_business::store::test_fixtures::build_test_user_store;
    use tiny_auth_business::store::test_fixtures::PUBLIC_CLIENT;
    use tiny_auth_business::store::test_fixtures::USER;
    use tiny_auth_business::store::ClientStore;
    use tiny_auth_business::store::UserStore;
    use tiny_auth_business::test_fixtures::build_test_token_creator;
    use tiny_auth_business::token::Token;
    use tiny_auth_business::userinfo_endpoint::test_fixtures::build_test_userinfo_handler;

    #[tokio::test]
    pub async fn missing_header_is_rejected() {
        let request = test::TestRequest::post().to_http_request();
        let query = Form(Request { access_token: None });

        let resp = post(query, request, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    pub async fn invalid_header_is_rejected() {
        let request = test::TestRequest::post()
            .insert_header(("authorization", "invalid"))
            .to_http_request();
        let query = Form(Request { access_token: None });

        let resp = post(query, request, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    pub async fn valid_token_is_returned() {
        let creator = build_test_token_creator();
        let user = build_test_user_store().get(USER).await.unwrap();
        let client = build_test_client_store().get(PUBLIC_CLIENT).await.unwrap();
        let token = creator.build_token(&user, &client, &Vec::new(), 0);
        let expected_userinfo = creator.build_token(&user, &client, &Vec::new(), 0);
        let request = test::TestRequest::post()
            .insert_header((
                "authorization",
                <&str as Into<String>>::into("Bearer ")
                    + &creator
                        .finalize_access_token(token.clone())
                        .unwrap()
                        .as_ref(),
            ))
            .to_http_request();
        let query = Form(Request { access_token: None });

        let resp = post(query, request, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Token<Userinfo>>(resp).await;
        assert_eq!(expected_userinfo, response);
    }

    fn build_test_handler() -> Data<Handler> {
        Data::new(Handler {
            handler: Arc::new(build_test_userinfo_handler()),
            cors_checker: Arc::new(CorsChecker::new(cors_lister())),
        })
    }
}
