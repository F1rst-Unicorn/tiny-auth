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
pub mod token;
pub mod userinfo;

use crate::protocol::oauth2::ProtocolError;

use actix_web::http::StatusCode;
use actix_web::HttpResponse;

use actix_session::Session;

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

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: ProtocolError,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
}

pub fn render_oauth_error_response(error: ProtocolError, description: &str) -> HttpResponse {
    match error {
        ProtocolError::InvalidClient => HttpResponse::Unauthorized(),
        _ => HttpResponse::BadRequest(),
    }
    .json(ErrorResponse {
        error,
        error_description: Some(description.to_string()),
        error_uri: None,
    })
}

pub fn server_error(tera: &Tera) -> HttpResponse {
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
    let mut result = String::new();
    for _ in 0..32 {
        let mut char = 'ö';
        while !char.is_ascii_alphanumeric() {
            char = rand::random::<u8>().into();
        }
        result.push(char);
    }
    result
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
