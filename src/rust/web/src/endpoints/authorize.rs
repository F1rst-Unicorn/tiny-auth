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
use super::render_template;
use crate::endpoints::server_error;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use log::debug;
use log::error;
use log::info;
use log::log_enabled;
use log::Level::Debug;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::sync::Arc;
use tera::Tera;
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc::OidcResponseType;
use tiny_auth_business::oidc::Prompt;
use tiny_auth_business::oidc::ProtocolError;
use tiny_auth_business::oidc::ResponseType;
use tiny_auth_business::scope::parse_scope_names;
use tiny_auth_business::store::ClientStore;

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
}

impl Request {
    pub fn get_response_types(&self) -> Vec<ResponseType> {
        self.response_type
            .as_deref()
            .and_then(parse_response_type)
            .unwrap()
    }

    pub fn encode_redirect_to_fragment(&self) -> bool {
        let response_types = self.get_response_types();
        response_types.contains(&ResponseType::Oidc(OidcResponseType::IdToken))
            || response_types.contains(&ResponseType::OAuth2(oauth2::ResponseType::Token))
    }
}

pub async fn handle(
    mut query: web::Query<Request>,
    tera: web::Data<Tera>,
    client_store: web::Data<Arc<dyn ClientStore>>,
    session: Session,
) -> HttpResponse {
    let redirect_uri = match query.redirect_uri.as_ref() {
        None => {
            debug!("missing redirect_uri");
            return render_invalid_redirect_uri_error(&tera);
        }
        Some(uri) => uri.clone(),
    };

    let client_id = match query.client_id.as_ref() {
        None => {
            debug!("missing client_id");
            return render_invalid_client_id_error(&tera);
        }
        Some(client_id) => client_id,
    };

    let client = match client_store.get(client_id) {
        None => {
            info!("client '{}' not found", client_id);
            return render_invalid_client_id_error(&tera);
        }
        Some(client) => client,
    };

    if !client.is_redirect_uri_valid(&redirect_uri) {
        info!(
            "invalid redirect_uri '{}' for client '{}'",
            redirect_uri, client_id
        );
        return render_invalid_redirect_uri_error(&tera);
    }

    let client_state = query.state.clone();

    if query.scope.is_none() {
        debug!("Missing scope");
        return return_error(
            &redirect_uri,
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing required parameter scope",
            &client_state,
            query.encode_redirect_to_fragment(),
        );
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

    query.scope.replace(scopes);

    let prompts = parse_prompt(&query.prompt);
    if (prompts.contains(&Prompt::Login)
        || prompts.contains(&Prompt::Consent)
        || prompts.contains(&Prompt::SelectAccount))
        && prompts.contains(&Prompt::None)
    {
        debug!("Contradicting prompt requirements");
        return return_error(
            &redirect_uri,
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "contradicting prompt requirements",
            &client_state,
            query.encode_redirect_to_fragment(),
        );
    }

    let response_type = match query.response_type.as_deref().map(parse_response_type) {
        None | Some(None) => {
            debug!("Missing or invalid response_type");
            return return_error(
                &redirect_uri,
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Invalid required parameter response_type",
                &client_state,
                false,
            );
        }
        Some(Some(response_type)) => response_type,
    };

    // https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
    if response_type.contains(&ResponseType::Oidc(OidcResponseType::IdToken))
        && query.nonce.is_none()
    {
        debug!("Missing required parameter nonce for implicit flow");
        return return_error(
            &redirect_uri,
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Invalid required parameter nonce",
            &client_state,
            query.encode_redirect_to_fragment(),
        );
    }

    if let Err(e) = session.insert(SESSION_KEY, serde_urlencoded::to_string(query.0).unwrap()) {
        error!("Failed to serialise session: {}", e);
        return server_error(&tera);
    }

    HttpResponse::SeeOther()
        .insert_header(("Location", "authenticate"))
        .finish()
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

fn render_invalid_client_id_error(tera: &Tera) -> HttpResponse {
    render_template("invalid_client_id.html.j2", StatusCode::BAD_REQUEST, tera)
}

fn render_invalid_redirect_uri_error(tera: &Tera) -> HttpResponse {
    render_template(
        "invalid_redirect_uri.html.j2",
        StatusCode::BAD_REQUEST,
        tera,
    )
}

pub fn return_error(
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
    use crate::endpoints::tests::build_test_tera;
    use actix_session::SessionExt;
    use actix_web::test;
    use actix_web::web::Data;
    use actix_web::web::Query;
    use tiny_auth_business::oauth2::ResponseType::Code;
    use tiny_auth_business::oauth2::ResponseType::Token;
    use tiny_auth_business::oidc::OidcResponseType::IdToken;
    use tiny_auth_business::oidc::ResponseType::OAuth2;
    use tiny_auth_business::oidc::ResponseType::Oidc;
    use tiny_auth_business::store::test_fixtures::build_test_client_store;
    use tiny_auth_business::store::test_fixtures::CONFIDENTIAL_CLIENT;
    use tiny_auth_business::store::test_fixtures::UNKNOWN_CLIENT_ID;
    use url::Url;

    #[test]
    async fn missing_client_id_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            scope: None,
            response_type: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    async fn missing_redirect_uri_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            scope: None,
            response_type: None,
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: None,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    async fn unknown_client_id_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            scope: None,
            response_type: None,
            client_id: Some(UNKNOWN_CLIENT_ID.to_string()),
            redirect_uri: None,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    async fn unregistered_redirect_uri_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let query = Query(Request {
            scope: None,
            response_type: None,
            client_id: Some(UNKNOWN_CLIENT_ID.to_string()),
            redirect_uri: Some("invalid".to_string()),
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    async fn missing_scope_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let client_store = build_test_client_store();
        let redirect_uri =
            client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            scope: None,
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

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

    #[test]
    async fn contradicting_prompts_are_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let client_store = build_test_client_store();
        let redirect_uri =
            client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            scope: Some("email".to_string()),
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            response_mode: None,
            nonce: None,
            display: None,
            prompt: Some("none login".to_string()),
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

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

    #[test]
    async fn missing_response_type_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let client_store = build_test_client_store();
        let redirect_uri =
            client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            scope: Some("email".to_string()),
            response_type: None,
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        });

        let resp = handle(
            query,
            build_test_tera(),
            Data::new(build_test_client_store()),
            session,
        )
        .await;

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

    #[test]
    async fn disallowed_scope_is_dropped() {
        let req = test::TestRequest::post().to_http_request();
        let client_store = build_test_client_store();
        let session = req.get_session();
        let redirect_uri =
            client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
        let client_state = "somestate".to_string();
        let request = Request {
            scope: Some("email profile".to_string()),
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        };
        let query = Query(request.clone());

        let resp = handle(query, build_test_tera(), Data::new(client_store), session).await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);

        let session = req.get_session();
        let first_request = parse_first_request(&session).unwrap();
        assert_eq!(Some("email".to_string()), first_request.scope);
    }

    #[test]
    async fn successful_authorization_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let client_store = build_test_client_store();
        let session = req.get_session();
        let redirect_uri =
            client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
        let client_state = "somestate".to_string();
        let request = Request {
            scope: Some("email".to_string()),
            response_type: Some("code".to_string()),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri.to_string()),
            state: Some(client_state.clone()),
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
        };
        let query = Query(request.clone());

        let resp = handle(query, build_test_tera(), Data::new(client_store), session).await;

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);

        let session = req.get_session();
        let first_request = parse_first_request(&session).unwrap();
        assert_eq!(request, first_request);
    }

    #[test]
    async fn single_response_types_are_parsed() {
        assert_eq!(Some(vec![OAuth2(Code)]), parse_response_type("code"));
        assert_eq!(Some(vec![OAuth2(Token)]), parse_response_type("token"));
        assert_eq!(Some(vec![Oidc(IdToken)]), parse_response_type("id_token"));
    }

    #[test]
    async fn composite_response_types_are_parsed() {
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
    async fn errors_are_reported() {
        assert_eq!(None, parse_response_type("code id_token invalid"));
    }
}
