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
use tiny_auth_business::serde::deserialise_empty_as_none;
use tiny_auth_business::token::Token;
use tiny_auth_business::token::TokenValidator;
use tracing::{debug, instrument};

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    access_token: Option<String>,
}

#[instrument(skip_all, fields(transport = "http"))]
pub async fn get(request: HttpRequest, handler: Data<Handler>) -> HttpResponse {
    post(Form(Request { access_token: None }), request, handler).await
}

#[instrument(skip_all, fields(transport = "http"))]
pub async fn post(
    query: Form<Request>,
    request: HttpRequest,
    handler: Data<Handler>,
) -> HttpResponse {
    let cors_check_result = handler.check_cors(&request);
    if let CorsCheckResult::IllegalOrigin = cors_check_result {
        return render_invalid_request();
    }

    match handler.handle(query, &request) {
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
        Err(Error::InvalidToken) => cors_check_result
            .with_headers(HttpResponse::Unauthorized())
            .append_header((
                "www-authenticate",
                "error=\"invalid_token\", error_description=\"Invalid token\"",
            ))
            .finish(),
    }
}

#[derive(Clone)]
pub struct Handler {
    validator: Arc<TokenValidator>,
    cors_checker: Arc<CorsChecker>,
}

impl Handler {
    fn check_cors<'a>(&self, request: &'a HttpRequest) -> CorsCheckResult<'a> {
        self.cors_checker.check(request)
    }

    fn handle(&self, query: Form<Request>, request: &HttpRequest) -> Result<Token, Error> {
        let token = Self::look_up_token(&query, request)?;

        match self.validator.validate::<Token>(&token) {
            None => {
                debug!("Invalid token");
                Err(Error::InvalidToken)
            }
            Some(token) => Ok(token),
        }
    }

    fn look_up_token(query: &Form<Request>, request: &HttpRequest) -> Result<String, Error> {
        if let Some(token) = &query.access_token {
            Ok(token.to_string())
        } else {
            match request.headers().get("Authorization") {
                Some(header) => match parse_bearer_authorization(header) {
                    Some(token) => Ok(token),
                    None => {
                        debug!("Invalid authorization header");
                        Err(Error::InvalidAuthorizationHeader)
                    }
                },
                None => {
                    debug!("Missing authorization header");
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
    use tiny_auth_business::token::TokenValidator;

    pub fn handler(validator: Arc<TokenValidator>, cors_checker: Arc<CorsChecker>) -> Handler {
        Handler {
            validator,
            cors_checker,
        }
    }
}

enum Error {
    InvalidAuthorizationHeader,
    MissingAuthorizationHeader,
    InvalidToken,
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
    use tiny_auth_business::test_fixtures::build_test_token_validator;
    use tiny_auth_business::token::Token;

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
        let request = test::TestRequest::post()
            .insert_header((
                "authorization",
                "Bearer ".to_string() + &creator.finalize(token.clone()).unwrap(),
            ))
            .to_http_request();
        let query = Form(Request { access_token: None });

        let resp = post(query, request, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Token>(resp).await;
        assert_eq!(token, response);
    }

    fn build_test_handler() -> Data<Handler> {
        Data::new(Handler {
            validator: Arc::new(build_test_token_validator()),
            cors_checker: Arc::new(CorsChecker::new(cors_lister())),
        })
    }
}
