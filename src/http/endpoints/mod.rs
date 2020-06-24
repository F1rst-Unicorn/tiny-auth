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
pub mod consent;
pub mod discovery;
pub mod token;
pub mod userinfo;

use crate::protocol::oauth2::ProtocolError as OAuthError;
use crate::protocol::oidc::ProtocolError;
use crate::util::generate_random_string;

use actix_web::http::HeaderValue;
use actix_web::http::StatusCode;
use actix_web::HttpResponse;

use actix_session::Session;

use url::Url;

use tera::Context;
use tera::Tera;

use log::debug;

use serde::de::Deserialize as _;
use serde::de::Visitor;
use serde::Deserializer;
use serde_derive::Deserialize;
use serde_derive::Serialize;

const CSRF_SESSION_KEY: &str = "c";

const CSRF_CONTEXT: &str = "csrftoken";
const ERROR_CONTEXT: &str = "error";
const TRIES_LEFT_CONTEXT: &str = "tries";

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: ProtocolError,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
}

pub fn method_not_allowed() -> HttpResponse {
    HttpResponse::MethodNotAllowed().body("method not allowed")
}

fn render_json_error(error: ProtocolError, description: &str) -> HttpResponse {
    match error {
        ProtocolError::OAuth2(OAuthError::InvalidClient) => HttpResponse::Unauthorized(),
        _ => HttpResponse::BadRequest(),
    }
    .json(ErrorResponse {
        error,
        error_description: Some(description.to_string()),
        error_uri: None,
    })
}

fn render_redirect_error(url: &mut Url, error: ProtocolError, description: &str) -> HttpResponse {
    url.query_pairs_mut()
        .append_pair("error", &format!("{}", error))
        .append_pair("error_description", description);

    HttpResponse::Found()
        .header("Location", url.as_str())
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
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", e);
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
            Ok(Some(reference)) => token == &reference,
            e => {
                debug!("token not found in session: {:#?}", e);
                false
            }
        },
    }
}

pub fn parse_basic_authorization(value: &HeaderValue) -> Option<(String, String)> {
    let credentials = parse_authorization(value, "Basic")?;
    let credentials = match base64::decode(credentials) {
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

pub fn parse_authorization(value: &HeaderValue, auth_type: &str) -> Option<String> {
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

fn deserialise_empty_as_none<'de, D: Deserializer<'de>>(
    value: D,
) -> Result<Option<String>, D::Error> {
    struct OptionVisitor {
        marker: std::marker::PhantomData<String>,
    }

    impl<'de> Visitor<'de> for OptionVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("option")
        }

        #[inline]
        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        #[inline]
        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            String::deserialize(deserializer).map(Some)
        }

        #[inline]
        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        #[doc(hidden)]
        fn __private_visit_untagged_option<D>(self, deserializer: D) -> Result<Self::Value, ()>
        where
            D: Deserializer<'de>,
        {
            Ok(String::deserialize(deserializer).ok())
        }
    }
    let mut result = value
        .deserialize_option(OptionVisitor {
            marker: std::marker::PhantomData,
        })
        .ok()
        .flatten();
    if result.is_some() && result.as_ref().unwrap().is_empty() {
        result = None;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {

    use super::*;

    use actix_web::test;
    use actix_web::web::BytesMut;
    use actix_web::HttpResponse;

    use actix_session::UserSession;

    use futures::stream::StreamExt;

    use serde::de::DeserializeOwned;
    use serde_derive::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Test {
        #[serde(default)]
        #[serde(deserialize_with = "deserialise_empty_as_none")]
        pub value: Option<String>,
    }

    #[test]
    pub fn empty_string_is_mapped_to_none() {
        let input = r#"value="#;
        let result = serde_urlencoded::from_str::<Test>(input).expect("invalid input");
        assert_eq!(None, result.value);
    }

    #[test]
    pub fn missing_value_is_none() {
        let input = r#""#;
        let result = serde_urlencoded::from_str::<Test>(input).expect("invalid input");
        assert_eq!(None, result.value);
    }

    #[test]
    pub fn value_is_some() {
        let input = r#"value=value"#;
        let result = serde_urlencoded::from_str::<Test>(input).expect("invalid input");
        assert_eq!(Some("value".to_string()), result.value);
    }

    #[test]
    pub fn verify_csrf_verification() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let token = "token".to_string();
        assert!(!is_csrf_valid(&None, &session));
        assert!(!is_csrf_valid(&Some(token.clone()), &session));

        session.set(CSRF_SESSION_KEY, &token).unwrap();
        assert!(!is_csrf_valid(&Some(token.clone() + "wrong"), &session));
        assert!(is_csrf_valid(&Some(token), &session));
    }

    pub async fn read_response<T: DeserializeOwned>(mut resp: HttpResponse) -> T {
        let mut body = resp.take_body();
        let mut bytes = BytesMut::new();
        while let Some(item) = body.next().await {
            bytes.extend_from_slice(&item.unwrap());
        }
        serde_json::from_slice::<T>(&bytes).expect("Failed to deserialize response")
    }
}
