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

//pub mod authenticate;
pub mod authorize;
//pub mod consent;
pub mod discovery;
pub mod health;
//pub mod token;
//pub mod userinfo;

use crate::protocol::oauth2::ProtocolError as OAuthError;
use crate::protocol::oidc::Prompt;
use crate::protocol::oidc::ProtocolError;
use crate::util::generate_random_string;
use crate::util::render_tera_error;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::convert::TryFrom;
use std::io::Cursor;
use std::ops::Deref;
use std::str::FromStr;

use rocket::response::Redirect;
use url::Url;

use tera::Context;
use tera::Tera;

use log::debug;
use log::error;

use rocket::form::FromFormField;
use rocket::http::ContentType;
use rocket::http::Header;
use rocket::http::Status;
use rocket::response::content::Html;
use rocket::response::ResponseBuilder;
use rocket::Response;

use serde::de::Deserialize as _;
use serde::de::Visitor;
use serde::Deserializer;
use serde_derive::Deserialize;
use serde_derive::Serialize;

const CSRF_SESSION_KEY: &str = "c";

const CSRF_CONTEXT: &str = "csrftoken";
const ERROR_CONTEXT: &str = "error";
const TRIES_LEFT_CONTEXT: &str = "tries";
const CLIENT_ID_CONTEXT: &str = "client";
const USER_NAME_CONTEXT: &str = "user";
const SCOPES_CONTEXT: &str = "scopes";
const LOGIN_HINT_CONTEXT: &str = "login_hint";
const COOKIE_NAME: &str = "session";

fn parse_prompt(prompt: &Option<String>) -> BTreeSet<Prompt> {
    match prompt {
        None => Default::default(),
        Some(value) => value
            .split(' ')
            .map(Prompt::try_from)
            .filter(Result::is_ok)
            .map(Result::unwrap)
            .collect(),
    }
}

fn parse_scope_names(names: &str) -> Vec<String> {
    names.split(' ').map(str::to_string).collect()
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: ProtocolError,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}
/*

/// When which HTTP code: https://tools.ietf.org/html/rfc6749#section-5.2
fn render_json_error(error: ProtocolError, description: &str) -> HttpResponse {
    match error {
        ProtocolError::OAuth2(OAuthError::InvalidClient) => HttpResponse::Unauthorized(),
        ProtocolError::OAuth2(OAuthError::UnauthorizedClient) => HttpResponse::Unauthorized(),
        _ => HttpResponse::BadRequest(),
    }
    .json(ErrorResponse {
        error,
        error_description: Some(description.to_string()),
        error_uri: None,
    })
}
 */
fn render_redirect_error<'r>(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> Redirect {
    Redirect::found(
        render_error_url(redirect_uri, error, description, state, encode_to_fragment).to_string(),
    )
}

fn render_error_url(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> Url {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");

    let error = ErrorResponse {
        error,
        error_description: Some(description.to_string()),
        error_uri: None,
        state: state.clone(),
    };

    let serialised_error = serde_urlencoded::to_string(error).expect("failed to serialize");
    if encode_to_fragment {
        url.set_fragment(Some(&serialised_error));
    } else {
        url.set_query(Some(&serialised_error))
    }

    url
}

fn render_redirect_error_with_base<'r>(
    mut base_response: ResponseBuilder<'r>,
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> Response<'r> {
    let url = render_error_url(redirect_uri, error, description, state, encode_to_fragment);
    base_response
        .header(Header::new("Location", url.to_string()))
        .finalize()
}

type Website = (Status, Html<String>);

fn server_error(tera: &Tera) -> Html<String> {
    render_template("500.html.j2", tera)
}

fn render_template(name: &str, tera: &Tera) -> Html<String> {
    render_template_with_context(name, tera, &Context::new())
}

fn render_template_with_context(name: &str, tera: &Tera, context: &Context) -> Html<String> {
    let body = tera.render(name, context);
    match body {
        Ok(body) => Html(body),
        Err(e) => {
            log::warn!("{}", render_tera_error(&e));
            server_error(tera)
        }
    }
}

/*
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
 */
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct NonEmptyString(
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    Option<String>,
);

impl From<Option<String>> for NonEmptyString {
    fn from(s: Option<String>) -> Self {
        Self(s)
    }
}

impl From<String> for NonEmptyString {
    fn from(s: String) -> Self {
        Self(Some(s))
    }
}

impl From<&str> for NonEmptyString {
    fn from(s: &str) -> Self {
        Self(Some(s.to_string()))
    }
}

impl FromStr for NonEmptyString {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl<'v> FromFormField<'v> for NonEmptyString {
    fn from_value(field: rocket::form::ValueField<'v>) -> rocket::form::Result<'v, Self> {
        Ok(match field.value {
            "" => Self(None),
            v => Self(Some(v.to_string())),
        })
    }

    fn default() -> Option<Self> {
        Some(Self(None))
    }
}

impl Deref for NonEmptyString {
    type Target = Option<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[allow(clippy::unnecessary_wraps)]
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

    use futures::stream::StreamExt;

    use serde::de::DeserializeOwned;
    use serde_derive::Deserialize;

    #[derive(Debug, Deserialize, Serialize)]
    struct Test {
        #[serde(default)]
        #[serde(deserialize_with = "deserialise_empty_as_none")]
        pub value: Option<String>,
    }

    #[test]
    pub fn plus_is_encoded() {
        let input = Test {
            value: Some("AI4qNF5I6XA+HH8b0KFobQ".to_string()),
        };
        let result = serde_urlencoded::to_string(&input).expect("invalid input");
        assert_eq!("value=AI4qNF5I6XA%2BHH8b0KFobQ", result);
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
    /*

    #[test]
    pub fn verify_wrong_csrf_verification() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let token = "token".to_string();
        assert!(!is_csrf_valid(&None, &session));
        assert!(!is_csrf_valid(&Some(token.clone()), &session));

        session.set(CSRF_SESSION_KEY, &token).unwrap();
        assert!(!is_csrf_valid(&Some(token.clone() + "wrong"), &session));
    }

    #[test]
    pub fn verify_csrf_verification() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let token = "token".to_string();
        assert!(!is_csrf_valid(&None, &session));
        assert!(!is_csrf_valid(&Some(token.clone()), &session));

        session.set(CSRF_SESSION_KEY, &token).unwrap();
        assert!(is_csrf_valid(&Some(token), &session));
    }

    pub async fn read_response<T: DeserializeOwned>(mut resp: HttpResponse) -> T {
        let mut body = resp.take_body();
        let mut bytes = BytesMut::new();
        while let Some(item) = body.next().await {
            bytes.extend_from_slice(&item.unwrap());
        }
        serde_json::from_slice::<T>(&bytes).expect("Failed to deserialize response")
    } */
}
