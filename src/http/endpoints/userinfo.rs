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

use super::deserialise_empty_as_none;
use super::parse_bearer_authorization;
use crate::business::token::TokenValidator;
use crate::domain::Token;

use log::debug;

use actix_web::web::Data;
use actix_web::web::Form;
use actix_web::HttpRequest;
use actix_web::HttpResponse;

use serde_derive::Deserialize;

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    access_token: Option<String>,
}

pub async fn handle(
    query: Form<Request>,
    headers: HttpRequest,
    validator: Data<TokenValidator>,
) -> HttpResponse {
    let token = if let Some(token) = &query.access_token {
        token.to_string()
    } else {
        match headers.headers().get("Authorization") {
            Some(header) => match parse_bearer_authorization(header) {
                Some(token) => token,
                None => {
                    debug!("Invalid authorization header");
                    return HttpResponse::Unauthorized()
                .header("www-authenticate", "error=\"invalid_request\", error_description=\"Invalid authorization header\"")
                .finish();
                }
            },
            None => {
                debug!("Missing authorization header");
                return HttpResponse::BadRequest()
                .header(
                    "www-authenticate",
                    "error=\"invalid_request\", error_description=\"Missing authorization header\"",
                )
                .finish();
            }
        }
    };

    let token = match validator.validate::<Token>(&token) {
        None => {
            debug!("Invalid token");
            return HttpResponse::Unauthorized()
                .header(
                    "www-authenticate",
                    "error=\"invalid_token\", error_description=\"Invalid token\"",
                )
                .finish();
        }
        Some(token) => token,
    };

    HttpResponse::Ok().json(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::token::Token;
    use crate::http::endpoints::tests::read_response;
    use crate::http::state::tests::build_test_client_store;
    use crate::http::state::tests::build_test_token_creator;
    use crate::http::state::tests::build_test_token_issuer;
    use crate::http::state::tests::build_test_token_validator;
    use crate::http::state::tests::build_test_user_store;
    use crate::store::tests::PUBLIC_CLIENT;
    use crate::store::tests::USER;

    use chrono::Duration;
    use chrono::Local;

    use actix_web::http;
    use actix_web::test;

    #[tokio::test]
    pub async fn missing_header_is_rejected() {
        let validator = build_test_token_validator();
        let request = test::TestRequest::post().to_http_request();
        let query = Form(Request { access_token: None });

        let resp = handle(query, request, validator).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    pub async fn invalid_header_is_rejected() {
        let validator = build_test_token_validator();
        let request = test::TestRequest::post()
            .header("authorization", "invalid")
            .to_http_request();
        let query = Form(Request { access_token: None });

        let resp = handle(query, request, validator).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    pub async fn expired_token_is_rejected() {
        let creator = build_test_token_creator();
        let validator = build_test_token_validator();
        let user = build_test_user_store().get(USER).unwrap();
        let client = build_test_client_store().get(PUBLIC_CLIENT).unwrap();
        let expiration = Duration::minutes(3);
        let request = test::TestRequest::post()
            .header(
                "authorization",
                "Bearer ".to_string()
                    + &creator
                        .create(Token::build(
                            &user,
                            &client,
                            &Vec::new(),
                            Local::now() - expiration,
                            Duration::zero(),
                            0,
                        ))
                        .unwrap(),
            )
            .to_http_request();
        let query = Form(Request { access_token: None });

        let resp = handle(query, request, validator).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    pub async fn valid_token_is_returned() {
        let creator = build_test_token_creator();
        let validator = build_test_token_validator();
        let user = build_test_user_store().get(USER).unwrap();
        let client = build_test_client_store().get(PUBLIC_CLIENT).unwrap();
        let expiration = Duration::minutes(3);
        let mut token = Token::build(
            &user,
            &client,
            &Vec::new(),
            Local::now() + expiration,
            expiration,
            0,
        );
        token.set_issuer(&build_test_token_issuer());
        let request = test::TestRequest::post()
            .header(
                "authorization",
                "Bearer ".to_string() + &creator.create(token.clone()).unwrap(),
            )
            .to_http_request();
        let query = Form(Request { access_token: None });

        let resp = handle(query, request, validator).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Token>(resp).await;
        assert_eq!(token, response);
    }
}
