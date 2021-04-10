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
use super::parse_prompt;
use super::parse_scope_names;
use super::render_error_url;
use super::render_template;
use super::NonEmptyString;
use super::Website;
use super::COOKIE_NAME;
use crate::http::state::CookieFactory;
use crate::protocol::oauth2;
use crate::protocol::oidc::OidcResponseType;
use crate::protocol::oidc::Prompt;
use crate::protocol::oidc::ProtocolError;
use crate::protocol::oidc::ResponseType;
use crate::store::ClientStore;

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::sync::Arc;

use serde_derive::Deserialize;
use serde_derive::Serialize;

use tera::Tera;

use log::debug;
use log::info;
use log::log_enabled;
use log::warn;
use log::Level::Debug;

use rocket::form::Form;
use rocket::form::FromForm;
use rocket::get;
use rocket::http::CookieJar;
use rocket::http::Status;
use rocket::post;
use rocket::request::FromRequest;
use rocket::request::Outcome;
use rocket::response::Redirect;
use rocket::State;

use async_trait::async_trait;

#[derive(Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize)]
pub struct SessionRequest {
    #[serde(rename = "a")]
    pub scope: NonEmptyString,

    #[serde(rename = "b")]
    pub response_type: NonEmptyString,

    #[serde(rename = "c")]
    pub client_id: String,

    #[serde(rename = "d")]
    pub redirect_uri: String,

    #[serde(default)]
    #[serde(rename = "e")]
    pub state: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "f")]
    pub response_mode: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "g")]
    pub nonce: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "h")]
    pub display: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "i")]
    pub prompt: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "j")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,

    #[serde(default)]
    #[serde(rename = "k")]
    pub ui_locales: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "l")]
    pub id_token_hint: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "m")]
    pub login_hint: NonEmptyString,

    #[serde(default)]
    #[serde(rename = "n")]
    pub acr_values: NonEmptyString,
}

impl From<Request> for SessionRequest {
    fn from(r: Request) -> Self {
        Self {
            scope: r.scope,
            response_type: r.response_type,
            client_id: r.client_id,
            redirect_uri: r.redirect_uri,
            state: r.state,
            response_mode: r.response_mode,
            nonce: r.nonce,
            display: r.display,
            prompt: r.prompt,
            max_age: r.max_age,
            ui_locales: r.ui_locales,
            id_token_hint: r.id_token_hint,
            login_hint: r.login_hint,
            acr_values: r.acr_values,
        }
    }
}

#[derive(FromForm, Debug, PartialEq, Eq, Clone, Default, Serialize)]
pub struct Request {
    pub scope: NonEmptyString,

    pub response_type: NonEmptyString,

    pub client_id: String,

    pub redirect_uri: String,

    pub state: NonEmptyString,

    pub response_mode: NonEmptyString,

    pub nonce: NonEmptyString,

    pub display: NonEmptyString,

    pub prompt: NonEmptyString,

    pub max_age: Option<i64>,

    pub ui_locales: NonEmptyString,

    pub id_token_hint: NonEmptyString,

    pub login_hint: NonEmptyString,

    pub acr_values: NonEmptyString,
}

impl Request {
    pub fn empty() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn get_response_types(&self) -> Vec<ResponseType> {
        self.response_type
            .0
            .as_deref()
            .map(parse_response_type)
            .flatten()
            .unwrap()
    }

    pub fn encode_redirect_to_fragment(&self) -> bool {
        let response_types = self.get_response_types();
        response_types.contains(&ResponseType::Oidc(OidcResponseType::IdToken))
            || response_types.contains(&ResponseType::OAuth2(oauth2::ResponseType::Token))
    }
}

pub struct Session<'r> {
    cookie_jar: &'r CookieJar<'r>,

    cookie_builder: CookieFactory,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq)]
struct SessionContent {
    #[serde(flatten)]
    first_request: SessionRequest,

    #[serde(default)]
    #[serde(rename = "o")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    username: Option<String>,

    #[serde(default)]
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<u64>,

    #[serde(default)]
    #[serde(rename = "q")]
    error_code: u64,

    #[serde(default)]
    #[serde(rename = "r")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tries_left: Option<u64>,
}

impl From<Request> for SessionContent {
    fn from(request: Request) -> Self {
        Self {
            first_request: request.into(),
            ..Self::default()
        }
    }
}

impl<'r> Session<'r> {
    fn set_initial_request(&'r self, request: Request) {
        let mut cookie = match self.cookie_jar.get_private(COOKIE_NAME) {
            Some(v) => v,
            None => self.cookie_builder.build(),
        };

        let content = SessionContent::from(request);

        let serialised_content = match serde_urlencoded::to_string(&content) {
            Err(e) => {
                warn!("Failed to set initial request to cookie: {}", e);
                return;
            }
            Ok(v) => v,
        };

        cookie.set_value(serialised_content);
        self.cookie_jar.add_private(cookie);
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for Session<'r> {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let cookie_builder = match request.guard::<State<'_, CookieFactory>>().await {
            Outcome::Success(v) => v,
            Outcome::Forward(_) => return Outcome::Forward(()),
            Outcome::Failure((status, _)) => return Outcome::Failure((status, ())),
        };

        FromRequest::from_request(request)
            .await
            .map(|cookie_jar| Self {
                cookie_jar,
                cookie_builder: cookie_builder.inner().clone(),
            })
            .map_failure(|(s, _)| (s, ()))
    }
}

#[get("/?<query..>")]
pub fn get(
    query: Request,
    tera: State<'_, Tera>,
    client_store: State<'_, Arc<dyn ClientStore>>,
    session: Session<'_>,
) -> Result<Redirect, Website> {
    handle(query, tera.inner(), client_store.inner().clone(), session)
}

#[post("/", data = "<query>")]
pub fn post(
    query: Form<Request>,
    tera: State<'_, Tera>,
    client_store: State<'_, Arc<dyn ClientStore>>,
    session: Session<'_>,
) -> Result<Redirect, Website> {
    handle(
        query.into_inner(),
        tera.inner(),
        client_store.inner().clone(),
        session,
    )
}

pub fn handle(
    mut query: Request,
    tera: &Tera,
    client_store: Arc<dyn ClientStore>,
    session: Session<'_>,
) -> Result<Redirect, Website> {
    let client = match client_store.get(&query.client_id) {
        None => {
            info!("client '{}' not found", query.client_id);
            return Err(render_invalid_client_id_error(&tera));
        }
        Some(client) => client,
    };

    if !client.is_redirect_uri_valid(&query.redirect_uri) {
        info!(
            "invalid redirect_uri '{}' for client '{}'",
            query.redirect_uri, query.client_id
        );
        return Err(render_invalid_redirect_uri_error(&tera));
    }

    let client_state = query.state.clone();

    if query.scope.is_none() {
        debug!("Missing scope");
        return Ok(return_error(
            &query.redirect_uri,
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing required parameter scope",
            &client_state,
            query.encode_redirect_to_fragment(),
        ));
    }

    let scopes = parse_scope_names(query.scope.as_deref().unwrap());
    let scopes: BTreeSet<String> = scopes.into_iter().collect();

    if log_enabled!(Debug) {
        let forbidden_scopes = scopes
            .difference(&client.allowed_scopes)
            .map(Clone::clone)
            .collect::<Vec<String>>()
            .join(" ");
        if !forbidden_scopes.is_empty() {
            debug!(
                "Client '{}' requested forbidden scopes '{}'. These are dropped silently",
                client.client_id, forbidden_scopes
            );
        }
    }

    let scopes = scopes
        .intersection(&client.allowed_scopes)
        .map(Clone::clone)
        .collect::<Vec<String>>()
        .join(" ");

    query.scope.0.replace(scopes);

    let prompts = parse_prompt(&query.prompt);
    if (prompts.contains(&Prompt::Login)
        || prompts.contains(&Prompt::Consent)
        || prompts.contains(&Prompt::SelectAccount))
        && prompts.contains(&Prompt::None)
    {
        debug!("Contradicting prompt requirements");
        return Ok(return_error(
            &query.redirect_uri,
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "contradicting prompt requirements",
            &client_state,
            query.encode_redirect_to_fragment(),
        ));
    }

    let response_type = match query.response_type.as_deref().map(parse_response_type) {
        None | Some(None) => {
            debug!("Missing or invalid response_type");
            return Ok(return_error(
                &query.redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Invalid required parameter response_type",
                &client_state,
                false,
            ));
        }
        Some(Some(response_type)) => response_type,
    };

    // https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
    if response_type.contains(&ResponseType::Oidc(OidcResponseType::IdToken))
        && query.nonce.is_none()
    {
        debug!("Missing required parameter nonce for implicit flow");
        return Ok(return_error(
            &query.redirect_uri,
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Invalid required parameter nonce",
            &client_state,
            query.encode_redirect_to_fragment(),
        ));
    }

    session.set_initial_request(query);

    Ok(Redirect::to("authenticate"))
}

pub fn parse_response_type(input: &str) -> Option<Vec<ResponseType>> {
    let mut result = Vec::new();
    for word in input.split(' ') {
        let parsed_word = ResponseType::try_from(word);
        match parsed_word {
            Err(e) => {
                debug!("invalid response_type {}. Error was: {}", word, e);
                return None;
            }
            Ok(response_type) => result.push(response_type),
        }
    }

    Some(result)
}

fn render_invalid_client_id_error(tera: &Tera) -> Website {
    (
        Status::BadRequest,
        render_template("invalid_client_id.html.j2", tera),
    )
}

fn render_invalid_redirect_uri_error(tera: &Tera) -> Website {
    (
        Status::BadRequest,
        render_template("invalid_redirect_uri.html.j2", tera),
    )
}

pub fn return_error(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> Redirect {
    Redirect::temporary(
        render_error_url(redirect_uri, error, description, state, encode_to_fragment).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::state::tests::build_test_client_store;
    use crate::http::tests::build_client;
    use crate::protocol::oauth2::ResponseType::Code;
    use crate::protocol::oauth2::ResponseType::Token;
    use crate::protocol::oidc::OidcResponseType::IdToken;
    use crate::protocol::oidc::ResponseType::OAuth2;
    use crate::protocol::oidc::ResponseType::Oidc;
    use crate::store::tests::CONFIDENTIAL_CLIENT;
    use crate::store::tests::UNKNOWN_CLIENT_ID;

    use url::Url;

    use rocket::http::ContentType;
    use rocket::http::Cookie;
    use rocket::http::Status;

    const TEST_STATE: &str = "somestate";

    #[test]
    fn unknown_client_id_is_rejected() {
        let client = build_client();
        let query = Request {
            client_id: UNKNOWN_CLIENT_ID.to_string(),
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn unregistered_redirect_uri_is_rejected() {
        let client = build_client();
        let query = Request {
            client_id: CONFIDENTIAL_CLIENT.to_string(),
            redirect_uri: "invalid".to_string(),
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn missing_scope_is_redirected() {
        let client = build_client();
        let client_store = build_test_client_store();
        let expected_url = client_store
            .get(CONFIDENTIAL_CLIENT)
            .map(|v| v.redirect_uris[0].to_string())
            .as_deref()
            .map(Url::parse)
            .map(Result::ok)
            .flatten()
            .unwrap();

        let query = Request {
            scope: Default::default(),
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(&query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::TemporaryRedirect);

        let url = response
            .headers()
            .get_one("Location")
            .map(Url::parse)
            .map(Result::ok)
            .flatten()
            .unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());
        let expected_error = format!(
            "{}",
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest)
        );
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("state".to_string(), TEST_STATE.into())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".into(), expected_error.clone())));
    }

    #[test]
    fn contradicting_prompts_are_rejected() {
        let client = build_client();
        let client_store = build_test_client_store();
        let expected_url = client_store
            .get(CONFIDENTIAL_CLIENT)
            .map(|v| v.redirect_uris[0].to_string())
            .as_deref()
            .map(Url::parse)
            .map(Result::ok)
            .flatten()
            .unwrap();

        let query = Request {
            prompt: "none login".into(),
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(&query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::TemporaryRedirect);

        let url = response
            .headers()
            .get_one("Location")
            .map(Url::parse)
            .map(Result::ok)
            .flatten()
            .unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());
        let expected_error = format!(
            "{}",
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest)
        );
        dbg!(&url);
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("state".to_string(), TEST_STATE.into())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".into(), expected_error.clone())));
    }
    #[test]
    fn missing_response_type_is_redirected() {
        let client = build_client();
        let client_store = build_test_client_store();
        let expected_url = client_store
            .get(CONFIDENTIAL_CLIENT)
            .map(|v| v.redirect_uris[0].to_string())
            .as_deref()
            .map(Url::parse)
            .map(Result::ok)
            .flatten()
            .unwrap();

        let query = Request {
            response_type: None.into(),
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(&query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::TemporaryRedirect);

        let url = response
            .headers()
            .get_one("Location")
            .map(Url::parse)
            .map(Result::ok)
            .flatten()
            .unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());
        let expected_error = format!(
            "{}",
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest)
        );
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("state".to_string(), TEST_STATE.into())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".into(), expected_error.clone())));
    }

    #[test]
    fn successful_authorization_is_redirected() {
        let client = build_client();
        let query = Request {
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(&query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::SeeOther);

        let url = response.headers().get_one("Location").unwrap();
        assert_eq!("authenticate", url);

        let session_request: SessionContent = response
            .cookies()
            .get_private(crate::http::state::tests::SESSION_COOKIE_NAME)
            .as_ref()
            .map(Cookie::value)
            .map(serde_urlencoded::from_str)
            .map(Result::ok)
            .flatten()
            .unwrap();

        assert_eq!(SessionContent::from(query), session_request);
    }

    #[test]
    fn disallowed_scope_is_dropped() {
        let client = build_client();
        let query = Request {
            scope: "email profile".into(),
            ..build_successful_request()
        };

        let response = client
            .post("/authorize")
            .header(ContentType::Form)
            .body(serde_urlencoded::to_string(&query).unwrap())
            .dispatch();

        assert_eq!(response.status(), Status::SeeOther);

        let url = response.headers().get_one("Location").unwrap();
        assert_eq!("authenticate", url);

        let session_request: SessionContent = response
            .cookies()
            .get_private(crate::http::endpoints::COOKIE_NAME)
            .as_ref()
            .map(Cookie::value)
            .map(serde_urlencoded::from_str)
            .map(Result::ok)
            .flatten()
            .unwrap();

        assert_eq!(
            "email",
            session_request.first_request.scope.as_deref().unwrap()
        )
    }

    #[test]
    pub fn single_response_types_are_parsed() {
        assert_eq!(Some(vec![OAuth2(Code)]), parse_response_type("code"));
        assert_eq!(Some(vec![OAuth2(Token)]), parse_response_type("token"));
        assert_eq!(Some(vec![Oidc(IdToken)]), parse_response_type("id_token"));
    }

    #[test]
    pub fn composite_response_types_are_parsed() {
        assert_eq!(
            Some(vec![OAuth2(Code), Oidc(IdToken)]),
            parse_response_type("code id_token")
        );
        assert_eq!(
            Some(vec![OAuth2(Token), Oidc(IdToken)]),
            parse_response_type("token id_token")
        );
        assert_eq!(
            Some(vec![Oidc(IdToken), OAuth2(Token), OAuth2(Code)]),
            parse_response_type("id_token token code")
        );
    }

    #[test]
    pub fn errors_are_reported() {
        assert_eq!(None, parse_response_type("code id_token invalid"));
    }

    fn build_successful_request() -> Request {
        let client_store = build_test_client_store();
        let redirect_uri =
            client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
        Request {
            scope: "email".into(),
            response_type: "code".into(),
            client_id: CONFIDENTIAL_CLIENT.into(),
            redirect_uri: redirect_uri.into(),
            state: TEST_STATE.into(),
            ..Request::empty()
        }
    }
}
