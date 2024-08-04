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

use super::{error_with_code, server_error};
use crate::session::AuthorizeSession;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tiny_auth_business::authorize_endpoint::{Error, Handler};
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc::OidcResponseType;
use tiny_auth_business::oidc::ProtocolError;
use tiny_auth_business::oidc::ResponseType;
use tiny_auth_business::serde::deserialise_empty_as_none;
use tiny_auth_business::template::web::{ErrorPage, WebTemplater};
use tracing::instrument;
use tracing::Level;
use web::Data;

pub const SESSION_KEY: &str = "a";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Request {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub response_type: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub client_id: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub state: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub response_mode: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub nonce: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub display: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub prompt: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<i64>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub ui_locales: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub id_token_hint: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub login_hint: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub acr_values: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub code_challenge_method: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub code_challenge: Option<String>,
}

impl Request {
    fn encode_redirect_to_fragment(&self) -> bool {
        let response_types = self
            .response_type
            .as_deref()
            .and_then(Handler::parse_response_type)
            .unwrap_or_default();
        response_types.contains(&ResponseType::Oidc(OidcResponseType::IdToken))
            || response_types.contains(&ResponseType::OAuth2(oauth2::ResponseType::Token))
    }
}

#[instrument(skip_all, name = "authorize")]
#[instrument(level = Level::DEBUG, skip_all, name = "flow", fields(
    state = query.state,
    nonce = query.nonce))]
pub async fn handle(
    query: web::Query<Request>,
    templater: Data<dyn WebTemplater<()>>,
    session: Session,
    handler: Data<Handler>,
) -> HttpResponse {
    let query = query.into_inner();
    let encode_redirect_to_fragment = query.encode_redirect_to_fragment();
    return match handler
        .handle(
            tiny_auth_business::authorize_endpoint::Request {
                scope: query.scope,
                response_type: query.response_type,
                client_id: query.client_id,
                redirect_uri: query.redirect_uri.clone(),
                nonce: query.nonce,
                state: query.state.clone(),
                prompt: query.prompt,
                max_age: query.max_age,
                login_hint: query.login_hint,
                code_challenge_method: query.code_challenge_method,
                code_challenge: query.code_challenge,
            },
            AuthorizeSession::from(session),
        )
        .await
        .map_err(|e| match e {
            Error::InvalidRedirectUri => render_invalid_redirect_uri_error(templater),
            Error::InvalidClientId => render_invalid_client_id_error(templater),
            Error::MissingScopes { redirect_uri } => return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing required parameter scope",
                &query.state,
                encode_redirect_to_fragment,
            ),
            Error::ContradictingPrompts { redirect_uri } => return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "contradicting prompt requirements",
                &query.state,
                encode_redirect_to_fragment,
            ),
            Error::CodeChallengeMethodInvalid { redirect_uri } => return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "code_challenge_method invalid",
                &query.state,
                encode_redirect_to_fragment,
            ),
            Error::CodeChallengeInvalid { redirect_uri } => return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "code_challenge invalid",
                &query.state,
                encode_redirect_to_fragment,
            ),
            Error::MissingResponseType { redirect_uri } => return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Invalid required parameter response_type",
                &query.state,
                encode_redirect_to_fragment,
            ),
            Error::MissingNonceForImplicitFlow { redirect_uri } => return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Invalid required parameter nonce",
                &query.state,
                encode_redirect_to_fragment,
            ),
            Error::ServerError => {
                server_error(templater.instantiate_error_page(ErrorPage::ServerError))
            }
        }) {
        Err(e) => e,
        Ok(_) => HttpResponse::SeeOther()
            .insert_header(("Location", "authenticate"))
            .finish(),
    };
}

fn render_invalid_client_id_error(templater: Data<dyn WebTemplater<()>>) -> HttpResponse {
    error_with_code(
        templater.instantiate_error_page(ErrorPage::InvalidClientId),
        StatusCode::BAD_REQUEST,
    )
}

fn render_invalid_redirect_uri_error(templater: Data<dyn WebTemplater<()>>) -> HttpResponse {
    error_with_code(
        templater.instantiate_error_page(ErrorPage::InvalidRedirectUri),
        StatusCode::BAD_REQUEST,
    )
}

fn return_error(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
    encode_to_fragment: bool,
) -> HttpResponse {
    super::render_redirect_error_with_base(
        HttpResponse::TemporaryRedirect(),
        redirect_uri,
        error,
        description,
        state,
        encode_to_fragment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::parse_first_request;
    use std::sync::Arc;

    use actix_session::SessionExt;
    use actix_web::test;
    use actix_web::web::Data;
    use actix_web::web::Query;
    use tiny_auth_business::authorize_endpoint::test_fixtures::handler;
    use tiny_auth_business::store::test_fixtures::build_test_client_store;
    use tiny_auth_business::store::test_fixtures::CONFIDENTIAL_CLIENT;
    use tiny_auth_business::store::test_fixtures::UNKNOWN_CLIENT_ID;
    use tiny_auth_business::store::ClientStore;
    use tiny_auth_business::template::test_fixtures::TestTemplater;
    use url::Url;

    #[test_log::test(actix_web::test)]
    async fn missing_client_id_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn missing_redirect_uri_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn unknown_client_id_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            client_id: Some(UNKNOWN_CLIENT_ID.to_string()),
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn unregistered_redirect_uri_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            client_id: Some(UNKNOWN_CLIENT_ID.to_string()),
            redirect_uri: Some("invalid".to_string()),
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn missing_scope_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let client_store = build_test_client_store();
        let redirect_uri = client_store
            .get(CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(&redirect_uri).unwrap();

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
            .any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[test_log::test(actix_web::test)]
    async fn contradicting_prompts_are_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let client_store = build_test_client_store();
        let redirect_uri = client_store
            .get(CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            scope: Some("email".to_string()),
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            prompt: Some("none login".to_string()),
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(&redirect_uri).unwrap();

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
            .any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[test_log::test(actix_web::test)]
    async fn missing_response_type_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let client_store = build_test_client_store();
        let redirect_uri = client_store
            .get(CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            scope: Some("email".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            ..Request::default()
        });

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(&redirect_uri).unwrap();

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
            .any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[test_log::test(actix_web::test)]
    async fn disallowed_scope_is_dropped() {
        let req = test::TestRequest::post().to_http_request();
        let client_store = build_test_client_store();
        let session = req.get_session();
        let redirect_uri = client_store
            .get(CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let request = Request {
            scope: Some("email profile".to_string()),
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            ..Request::default()
        };
        let query = Query(request.clone());

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);

        let session = req.get_session();
        let first_request = parse_first_request(&session).unwrap();
        assert_eq!(vec!["email".to_string()], first_request.scopes);
    }

    #[test_log::test(actix_web::test)]
    async fn successful_authorization_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let client_store = build_test_client_store();
        let session = req.get_session();
        let redirect_uri = client_store
            .get(CONFIDENTIAL_CLIENT)
            .await
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let request = Request {
            scope: Some("email".to_string()),
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            ..Request::default()
        };
        let query = Query(request.clone());

        let resp = handle(query, build_test_templater(), session, build_test_handler()).await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);
    }

    fn build_test_handler() -> Data<Handler> {
        Data::new(handler())
    }

    fn build_test_templater() -> Data<dyn WebTemplater<()>> {
        Data::from(Arc::new(TestTemplater) as Arc<dyn WebTemplater<_>>)
    }
}
