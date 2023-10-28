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
use super::parse_basic_authorization;
use crate::cors::CorsCheckResult;
use crate::cors::CorsChecker;
use crate::endpoints::render_json_error;
use actix_web::web;
use actix_web::web::Form;
use actix_web::HttpRequest;
use actix_web::HttpResponse;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::sync::Arc;
use tiny_auth_business::oauth2;
use tiny_auth_business::oauth2::GrantType;
use tiny_auth_business::oidc::ProtocolError;
use tiny_auth_business::scope::Scope;
use tiny_auth_business::token_endpoint::Error;

#[derive(Deserialize)]
pub struct Request {
    grant_type: Option<GrantType>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    code: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    redirect_uri: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    client_id: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    client_secret: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    scope: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    username: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    password: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    refresh_token: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    client_assertion: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    client_assertion_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    access_token: String,

    token_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

pub async fn post(
    headers: HttpRequest,
    request: Form<Request>,
    handler: web::Data<Handler>,
) -> HttpResponse {
    let cors_check_result = handler.check_cors(&headers);
    let grant_type = match &request.grant_type {
        None => {
            return render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing parameter grant_type",
            );
        }
        Some(grant_type) => grant_type.to_owned(),
    };

    let (token, refresh_token, scopes) = match handler
        .grant_tokens(&headers, request, grant_type)
        .await
        .map_err(|e| match e {
            Error::MissingRefreshToken => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing refresh token",
            ),
            Error::InvalidRefreshToken => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                "Invalid refresh token",
            ),
            Error::MissingRedirectUri => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing parameter redirect_uri",
            ),
            Error::MissingAuthorizationCode => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing parameter code",
            ),
            Error::InvalidAuthenticationToken(protocol_error) => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(protocol_error),
                "token is invalid",
            ),
            Error::InvalidAuthenticationTokenType => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "client_assertion_type is invalid",
            ),
            Error::InvalidAuthorizationHeader => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                "Invalid authorization header",
            ),
            Error::MissingAuthorizationHeader => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                "Missing authorization header",
            ),
            Error::WrongClientIdOrPassword => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::UnauthorizedClient),
                "client id or password wrong",
            ),
            Error::MissingClientId => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::UnauthorizedClient),
                "Missing parameter client_id",
            ),
            Error::ConfidentialClientMustAutenticate => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::UnauthorizedClient),
                "Confidential client has to authenticate",
            ),
            Error::InvalidAuthorizationCode => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                "Invalid code",
            ),
            Error::MissingUsername => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing username",
            ),
            Error::MissingPassword => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing password",
            ),
            Error::WrongUsernameOrPassword(message) => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                &message,
            ),
            Error::TokenEncodingFailed => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::ServerError),
                "token encoding failed",
            ),
            Error::RefreshTokenEncodingFailed => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::ServerError),
                "refresh token encoding failed",
            ),
            Error::UnsupportedGrantType => render_json_error(
                cors_check_result,
                ProtocolError::OAuth2(oauth2::ProtocolError::UnsupportedGrantType),
                "invalid grant_type",
            ),
        }) {
        Err(e) => return e,
        Ok(v) => v,
    };

    cors_check_result
        .with_headers(HttpResponse::Ok())
        .json(Response {
            access_token: token.clone(),
            token_type: "bearer".to_string(),
            expires_in: Some(60),
            refresh_token,
            scope: Some(
                scopes
                    .into_iter()
                    .map(|v| v.name)
                    .collect::<Vec<String>>()
                    .join(" "),
            ),
            id_token: Some(token),
        })
}

#[derive(Clone)]
pub struct Handler {
    handler: Arc<tiny_auth_business::token_endpoint::Handler>,
    cors_checker: Arc<CorsChecker>,
}

impl Handler {
    pub fn new(
        handler: Arc<tiny_auth_business::token_endpoint::Handler>,
        cors_checker: Arc<CorsChecker>,
    ) -> Self {
        Self {
            handler,
            cors_checker,
        }
    }

    fn check_cors<'a>(&self, request: &'a HttpRequest) -> CorsCheckResult<'a> {
        self.cors_checker.check(request)
    }

    async fn grant_tokens(
        &self,
        headers: &HttpRequest,
        mut request: Form<Request>,
        grant_type: GrantType,
    ) -> Result<(String, Option<String>, Vec<Scope>), Error> {
        self.handler
            .grant_tokens(tiny_auth_business::token_endpoint::Request {
                basic_authentication: headers
                    .headers()
                    .get("Authorization")
                    .and_then(parse_basic_authorization),
                grant_type,
                client_id: request.client_id.take(),
                client_secret: request.client_secret.take(),
                code: request.code.take(),
                redirect_uri: request.redirect_uri.take(),
                scope: request.scope.take(),
                username: request.username.take(),
                password: request.password.take(),
                refresh_token: request.refresh_token.take(),
                client_assertion: request.client_assertion.take(),
                client_assertion_type: request.client_assertion_type.take(),
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::tests::read_response;
    use crate::endpoints::ErrorResponse;
    use actix_web::http;
    use actix_web::test::TestRequest;
    use actix_web::web::Data;
    use actix_web::web::Form;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use chrono::offset::Local;
    use chrono::Duration;
    use test_log::test;
    use tiny_auth_business::cors::test_fixtures::build_test_cors_lister;
    use tiny_auth_business::oauth2::ProtocolError;
    use tiny_auth_business::oidc::ProtocolError as OidcError;
    use tiny_auth_business::store::test_fixtures::build_test_auth_code_store;
    use tiny_auth_business::store::test_fixtures::build_test_client_store;
    use tiny_auth_business::store::test_fixtures::build_test_scope_store;
    use tiny_auth_business::store::test_fixtures::build_test_user_store;
    use tiny_auth_business::store::test_fixtures::CONFIDENTIAL_CLIENT;
    use tiny_auth_business::store::test_fixtures::PUBLIC_CLIENT;
    use tiny_auth_business::store::test_fixtures::USER;
    use tiny_auth_business::store::AuthorizationCodeStore;
    use tiny_auth_business::store::ClientStore;
    use tiny_auth_business::store::UserStore;
    use tiny_auth_business::test_fixtures::build_test_authenticator;
    use tiny_auth_business::test_fixtures::build_test_issuer_config;
    use tiny_auth_business::test_fixtures::build_test_token_creator;
    use tiny_auth_business::test_fixtures::build_test_token_issuer;
    use tiny_auth_business::test_fixtures::build_test_token_validator;
    use tiny_auth_business::token::RefreshToken;
    use tiny_auth_business::token::Token;

    #[test(actix_rt::test)]
    async fn missing_grant_type_is_rejected() {
        let req = TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: None,
            code: Some("fdsa".to_string()),
            client_id: None,
            client_secret: None,
            redirect_uri: Some("fdsa".to_string()),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn unknown_authorization_is_rejected() {
        let req = TestRequest::post()
            .insert_header(("Authorization", "Invalid"))
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: None,
            client_secret: None,
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn invalid_base64_password_is_rejected() {
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic invalid"))
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: None,
            client_secret: None,
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn invalid_utf8_password_is_rejected() {
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic changeme"))
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: None,
            client_secret: None,
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn missing_password_is_rejected() {
        let req = TestRequest::post()
            .insert_header((
                "Authorization",
                "Basic ".to_string() + &STANDARD.encode("username".as_bytes()),
            ))
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: None,
            client_secret: None,
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn issue_valid_token_for_correct_password() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                "",
                Local::now(),
                Local::now(),
                Some("nonce".to_string()),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: None,
            client_secret: None,
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler_with_store(auth_code_store)).await;

        assert_eq!(http::StatusCode::OK, resp.status());
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(Some("".to_string()), response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[test(actix_rt::test)]
    async fn issue_valid_token_with_id_token_for_correct_password() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                "",
                Local::now(),
                Local::now(),
                Some("nonce".to_string()),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: None,
            client_secret: None,
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler_with_store(auth_code_store)).await;

        assert_eq!(http::StatusCode::OK, resp.status());
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(Some("".to_string()), response.scope);

        let token = build_test_token_validator().validate::<Token>(&response.id_token.unwrap());
        assert!(token.is_some());
        let token = token.unwrap();
        assert_eq!("nonce".to_string(), token.nonce);
    }

    #[test(actix_rt::test)]
    async fn public_client_cannot_get_access_token() {
        let auth = PUBLIC_CLIENT.to_string() + ":" + PUBLIC_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::ClientCredentials),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn confidential_client_gets_access_token() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::ClientCredentials),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(Some("".to_string()), response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[test(actix_rt::test)]
    async fn missing_username_is_rejected() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: Some(USER.to_string()),
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn missing_password_is_rejected_with_password_grant() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: Some(USER.to_string()),
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn public_client_cannot_use_password_grant() {
        let auth = PUBLIC_CLIENT.to_string() + ":" + PUBLIC_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[test(actix_rt::test)]
    async fn confidential_client_can_use_password_grant() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(Some("".to_string()), response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[test(actix_rt::test)]
    async fn missing_refresh_token_is_rejected() {
        let req = TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test(actix_rt::test)]
    async fn invalid_refresh_token_is_rejected() {
        let req = TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some("dummy".to_string()),
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(http::StatusCode::BAD_REQUEST, resp.status());
    }

    #[test(actix_rt::test)]
    async fn invalid_client_credentials_with_refresh_token_are_rejected() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":wrong";
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();

        let token_creator = build_test_token_creator();
        let token = Token::build(
            &build_test_user_store().get(USER).unwrap(),
            &build_test_client_store().get(CONFIDENTIAL_CLIENT).unwrap(),
            &Vec::new(),
            Local::now(),
            Duration::minutes(3),
            0,
        );
        let refresh_token = token_creator
            .create_refresh_token(RefreshToken::from(token, Duration::minutes(1), &Vec::new()))
            .unwrap();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some(refresh_token),
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[test(actix_rt::test)]
    async fn refresh_token_from_different_client_is_rejected() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();

        let token_creator = build_test_token_creator();
        let mut token = Token::build(
            &build_test_user_store().get(USER).unwrap(),
            &build_test_client_store().get(PUBLIC_CLIENT).unwrap(),
            &Vec::new(),
            Local::now(),
            Duration::minutes(3),
            0,
        );
        token.set_issuer(&build_test_token_issuer());
        let refresh_token = token_creator
            .create_refresh_token(RefreshToken::from(token, Duration::minutes(1), &Vec::new()))
            .unwrap();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some(refresh_token),
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(http::StatusCode::BAD_REQUEST, resp.status());
    }

    #[test(actix_rt::test)]
    async fn successful_refresh_token_authentication() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = STANDARD.encode(auth);
        let req = TestRequest::post()
            .insert_header(("Authorization", "Basic ".to_string() + &encoded_auth))
            .to_http_request();

        let token_creator = build_test_token_creator();
        let mut token = Token::build(
            &build_test_user_store().get(USER).unwrap(),
            &build_test_client_store().get(CONFIDENTIAL_CLIENT).unwrap(),
            &Vec::new(),
            Local::now(),
            Duration::minutes(3),
            0,
        );
        token.set_issuer(&build_test_token_issuer());
        let refresh_token = token_creator
            .create_refresh_token(RefreshToken::from(token, Duration::minutes(1), &Vec::new()))
            .unwrap();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some(refresh_token),
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(Some("".to_string()), response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[test(actix_rt::test)]
    async fn successful_authentication_with_secret_as_post_parameter() {
        let req = TestRequest::post().to_http_request();

        let token_creator = build_test_token_creator();
        let mut token = Token::build(
            &build_test_user_store().get(USER).unwrap(),
            &build_test_client_store().get(CONFIDENTIAL_CLIENT).unwrap(),
            &Vec::new(),
            Local::now(),
            Duration::minutes(3),
            0,
        );
        token.set_issuer(&build_test_token_issuer());
        let refresh_token = token_creator
            .create_refresh_token(RefreshToken::from(token, Duration::minutes(1), &Vec::new()))
            .unwrap();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            client_secret: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some(refresh_token),
            client_assertion: None,
            client_assertion_type: None,
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(Some("".to_string()), response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    fn build_test_handler() -> Data<Handler> {
        build_test_handler_with_store(build_test_auth_code_store())
    }

    fn build_test_handler_with_store(
        auth_code_store: Arc<dyn AuthorizationCodeStore>,
    ) -> Data<Handler> {
        Data::new(Handler {
            handler: Arc::new(tiny_auth_business::token_endpoint::Handler::new(
                build_test_client_store(),
                build_test_user_store(),
                auth_code_store,
                build_test_token_creator(),
                Arc::new(build_test_authenticator()),
                Arc::new(build_test_token_validator()),
                build_test_scope_store(),
                build_test_issuer_config(),
            )),
            cors_checker: Arc::new(CorsChecker::new(build_test_cors_lister())),
        })
    }
}
