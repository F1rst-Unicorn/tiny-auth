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

#[derive(Deserialize, Default)]
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

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    code_verifier: Option<String>,
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
                pkce_verifier: request.code_verifier.take(),
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
    use test_log::test;
    use tiny_auth_business::cors::test_fixtures::cors_lister;
    use tiny_auth_business::oauth2::ProtocolError;
    use tiny_auth_business::oidc::ProtocolError as OidcError;
    use tiny_auth_business::store::test_fixtures::build_test_auth_code_store;
    use tiny_auth_business::store::test_fixtures::build_test_client_store;
    use tiny_auth_business::store::test_fixtures::build_test_scope_store;
    use tiny_auth_business::store::test_fixtures::build_test_user_store;
    use tiny_auth_business::test_fixtures::build_test_authenticator;
    use tiny_auth_business::test_fixtures::build_test_issuer_config;
    use tiny_auth_business::test_fixtures::build_test_token_creator;
    use tiny_auth_business::test_fixtures::build_test_token_validator;

    #[test(actix_rt::test)]
    async fn missing_grant_type_is_rejected() {
        let req = TestRequest::post().to_http_request();
        let form = Form(Request {
            code: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
            ..Request::default()
        });

        let resp = post(req, form, build_test_handler()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    fn build_test_handler() -> Data<Handler> {
        let auth_code_store = build_test_auth_code_store();
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
            cors_checker: Arc::new(CorsChecker::new(cors_lister())),
        })
    }
}
