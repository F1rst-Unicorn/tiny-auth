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

pub mod authenticate;
pub mod authorize;
pub mod cert;
pub mod consent;
pub mod discovery;
pub mod health;
pub mod token;
pub mod userinfo;
pub mod webapp_root;

use crate::cors::render_invalid_request;
use crate::cors::CorsCheckResult;
use crate::cors::CorsChecker;
use actix_session::Session;
use actix_web::http::header::HeaderValue;
use actix_web::http::StatusCode;
use actix_web::HttpResponseBuilder;
use actix_web::{HttpRequest, HttpResponse};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::debug;
use serde::Serialize as BaseSerialize;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tera::Context;
use tera::Tera;
use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_business::oauth2::ProtocolError as OAuthError;
use tiny_auth_business::oidc::ProtocolError;
use tiny_auth_business::scope::render_tera_error;
use tiny_auth_business::store::memory::generate_random_string;
use url::Url;

const CSRF_SESSION_KEY: &str = "c";

const CSRF_CONTEXT: &str = "csrftoken";
const ERROR_CONTEXT: &str = "error";
const TRIES_LEFT_CONTEXT: &str = "tries";
const CLIENT_ID_CONTEXT: &str = "client";
const USER_NAME_CONTEXT: &str = "user";
const SCOPES_CONTEXT: &str = "scopes";
const LOGIN_HINT_CONTEXT: &str = "login_hint";

fn parse_first_request(session: &Session) -> Option<AuthorizeRequestState> {
    match session.get::<AuthorizeRequestState>(authorize::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited request, lacks authorization session key");
            None
        }
        Ok(req) => req,
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: ProtocolError,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
}

pub async fn method_not_allowed() -> HttpResponse {
    HttpResponse::MethodNotAllowed().body("method not allowed")
}

pub async fn not_found() -> HttpResponse {
    HttpResponse::NotFound().body("not found")
}

fn render_cors_result(
    cors_lister: Arc<dyn CorsLister>,
    request: &HttpRequest,
    response: impl BaseSerialize,
) -> HttpResponse {
    match CorsChecker::new(cors_lister.clone()).check(request) {
        CorsCheckResult::IllegalOrigin => render_invalid_request(),
        approved @ (CorsCheckResult::ApprovedOrigin(_) | CorsCheckResult::NoOrigin) => approved
            .with_headers(HttpResponse::Ok())
            .content_type("application/json")
            .json(response),
    }
}

/// When which HTTP code: https://tools.ietf.org/html/rfc6749#section-5.2
fn render_json_error(
    cors_check_result: CorsCheckResult,
    error: ProtocolError,
    description: &str,
) -> HttpResponse {
    cors_check_result
        .with_headers(match error {
            ProtocolError::OAuth2(OAuthError::InvalidClient) => HttpResponse::Unauthorized(),
            ProtocolError::OAuth2(OAuthError::UnauthorizedClient) => HttpResponse::Unauthorized(),
            _ => HttpResponse::BadRequest(),
        })
        .json(ErrorResponse {
            error,
            error_description: Some(description.to_string()),
            error_uri: None,
        })
}

fn render_redirect_error(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> HttpResponse {
    render_redirect_error_with_base(
        HttpResponse::Found(),
        redirect_uri,
        error,
        description,
        state,
        encode_to_fragment,
    )
}

fn render_redirect_error_with_base(
    mut base_response: HttpResponseBuilder,
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> HttpResponse {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");

    let mut response_parameters = BTreeMap::new();
    response_parameters.insert("error", format!("{}", error));
    response_parameters.insert("error_description", description.to_string());
    state
        .clone()
        .map(|v| response_parameters.insert("state", v));

    if encode_to_fragment {
        let fragment =
            serde_urlencoded::to_string(response_parameters).expect("failed to serialize");
        url.set_fragment(Some(&fragment));
    } else {
        url.query_pairs_mut().extend_pairs(response_parameters);
    }

    base_response
        .append_header(("Location", url.as_str()))
        .finish()
}

fn server_error(tera: &Tera) -> HttpResponse {
    render_template("500.html.j2", StatusCode::INTERNAL_SERVER_ERROR, tera)
}

fn render_template(name: &str, code: StatusCode, tera: &Tera) -> HttpResponse {
    render_template_with_context(name, code, tera, &Context::new())
}

fn render_template_with_context(
    name: &str,
    code: StatusCode,
    tera: &Tera,
    context: &Context,
) -> HttpResponse {
    let body = tera.render(name, context);
    match body {
        Ok(body) => HttpResponse::build(code)
            .insert_header(("Content-Type", "text/html"))
            .body(body),
        Err(e) => {
            log::warn!("{}", render_tera_error(&e));
            server_error(tera)
        }
    }
}

fn generate_csrf_token() -> String {
    generate_random_string(32)
}

fn is_csrf_valid(input_token: &Option<String>, session: &Session) -> bool {
    match input_token {
        None => false,
        Some(token) => match session.get::<String>(CSRF_SESSION_KEY) {
            Ok(Some(reference)) => {
                session.remove(CSRF_SESSION_KEY);
                token == &reference
            }
            e => {
                debug!("token not found in session: {:#?}", e);
                false
            }
        },
    }
}

pub fn parse_basic_authorization(value: &HeaderValue) -> Option<(String, String)> {
    let credentials = parse_authorization(value, "Basic")?;
    let credentials = match STANDARD.decode(credentials) {
        Err(e) => {
            debug!("base64 decoding of authorization header failed. {}", e);
            return None;
        }
        Ok(cred) => cred,
    };

    let credentials = match String::from_utf8(credentials) {
        Err(e) => {
            debug!("utf-8 decoding of authorization header failed. {}", e);
            return None;
        }
        Ok(cred) => cred,
    };

    let split: Vec<String> = credentials.splitn(2, ':').map(str::to_string).collect();
    if split.len() == 2 {
        Some((split[0].clone(), split[1].clone()))
    } else {
        None
    }
}

pub fn parse_bearer_authorization(value: &HeaderValue) -> Option<String> {
    parse_authorization(value, "Bearer")
}

fn parse_authorization(value: &HeaderValue, auth_type: &str) -> Option<String> {
    let auth_type = auth_type.to_string() + " ";
    let value = match value.to_str() {
        Err(e) => {
            debug!("decoding of authorization header failed. {}", e);
            return None;
        }
        Ok(value) => value,
    };

    if !value.starts_with(&auth_type) {
        debug!("Malformed HTTP basic authorization header '{}'", value);
        return None;
    }
    Some(value.replacen(&auth_type, "", 1))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::tera::load_template_engine;
    use actix_session::SessionExt;
    use actix_web::body::to_bytes;
    use actix_web::test;
    use actix_web::web::BytesMut;
    use actix_web::web::Data;
    use actix_web::HttpResponse;
    use serde::de::DeserializeOwned;
    use serde_derive::Deserialize;
    use tiny_auth_business::authenticator::Authenticator;
    use tiny_auth_business::serde::deserialise_empty_as_none;

    #[derive(Debug, Deserialize, Serialize)]
    struct Test {
        #[serde(default)]
        #[serde(deserialize_with = "deserialise_empty_as_none")]
        pub value: Option<String>,
    }

    #[test]
    async fn plus_is_encoded() {
        let input = Test {
            value: Some("AI4qNF5I6XA+HH8b0KFobQ".to_string()),
        };
        let result = serde_urlencoded::to_string(&input).expect("invalid input");
        assert_eq!("value=AI4qNF5I6XA%2BHH8b0KFobQ", result);
    }

    #[test]
    async fn empty_string_is_mapped_to_none() {
        let input = r#"value="#;
        let result = serde_urlencoded::from_str::<Test>(input).expect("invalid input");
        assert_eq!(None, result.value);
    }

    #[test]
    async fn missing_value_is_none() {
        let input = r#""#;
        let result = serde_urlencoded::from_str::<Test>(input).expect("invalid input");
        assert_eq!(None, result.value);
    }

    #[test]
    async fn value_is_some() {
        let input = r#"value=value"#;
        let result = serde_urlencoded::from_str::<Test>(input).expect("invalid input");
        assert_eq!(Some("value".to_string()), result.value);
    }

    #[test]
    async fn verify_wrong_csrf_verification() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let token = "token".to_string();
        assert!(!is_csrf_valid(&None, &session));
        assert!(!is_csrf_valid(&Some(token.clone()), &session));

        session.insert(CSRF_SESSION_KEY, &token).unwrap();
        assert!(!is_csrf_valid(&Some(token.clone() + "wrong"), &session));
    }

    #[test]
    async fn verify_csrf_verification() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let token = "token".to_string();
        assert!(!is_csrf_valid(&None, &session));
        assert!(!is_csrf_valid(&Some(token.clone()), &session));

        session.insert(CSRF_SESSION_KEY, &token).unwrap();
        assert!(is_csrf_valid(&Some(token), &session));
    }

    #[test(actix_rt::test)]
    async fn unknown_authorization_is_rejected() {
        let actual = parse_basic_authorization(&HeaderValue::from_str("Invalid").unwrap());
        assert_eq!(None, actual);
    }

    #[test(actix_rt::test)]
    async fn invalid_base64_password_is_rejected() {
        let actual = parse_basic_authorization(&HeaderValue::from_str("Basic invalid").unwrap());
        assert_eq!(None, actual);
    }

    #[test(actix_rt::test)]
    async fn invalid_utf8_password_is_rejected() {
        let actual = parse_basic_authorization(&HeaderValue::from_str("Basic changeme").unwrap());
        assert_eq!(None, actual);
    }

    #[test(actix_rt::test)]
    async fn missing_password_is_rejected() {
        let actual = parse_basic_authorization(
            &HeaderValue::from_str(
                &("Basic ".to_string() + &STANDARD.encode("username".as_bytes())),
            )
            .unwrap(),
        );
        assert_eq!(None, actual);
    }

    pub async fn read_response<T: DeserializeOwned>(resp: HttpResponse) -> T {
        let x = to_bytes(resp.into_body()).await;
        let mut bytes = BytesMut::new();
        if let Ok(item) = x {
            bytes.extend_from_slice(&item);
        }
        serde_json::from_slice::<T>(&bytes).expect("Failed to deserialize response")
    }

    pub fn build_test_tera() -> Data<Tera> {
        Data::new(
            load_template_engine(
                &(env!("CARGO_MANIFEST_DIR").to_string() + "/../../static/"),
                "",
            )
            .unwrap(),
        )
    }

    pub fn build_test_authenticator() -> Data<Authenticator> {
        Data::new(tiny_auth_business::authenticator::test_fixtures::authenticator())
    }
}
