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
use super::render_template;
use crate::http::endpoints::server_error;
use crate::http::state;
use crate::protocol::oauth2::ProtocolError;
use crate::protocol::oauth2::ResponseType;

use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use serde_derive::Deserialize;
use serde_derive::Serialize;

use tera::Tera;

use url::Url;

use log::debug;
use log::error;
use log::info;

pub const SESSION_KEY: &str = "a";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Request {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub scope: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<ResponseType>,

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
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    pub max_age: Option<String>,

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

pub async fn get(
    query: web::Query<Request>,
    state: web::Data<state::State>,
    session: Session,
) -> HttpResponse {
    post(query, state, session).await
}

pub async fn post(
    query: web::Query<Request>,
    state: web::Data<state::State>,
    session: Session,
) -> HttpResponse {
    if query.client_id.is_none() {
        debug!("missing client_id");
        return render_invalid_client_id_error(&state.tera);
    }

    if query.redirect_uri.is_none() {
        debug!("missing redirect_uri");
        return render_invalid_redirect_uri_error(&state.tera);
    }

    let redirect_uri = query.redirect_uri.as_ref().unwrap();
    let client_id = query.client_id.as_ref().unwrap();

    let client = state.client_store.get(client_id);

    if client.is_none() {
        info!("client '{}' not found", client_id);
        return render_invalid_client_id_error(&state.tera);
    }
    let client = client.expect("checked before");

    if !client.is_redirect_uri_valid(redirect_uri) {
        info!(
            "invalid redirect_uri '{}' for client '{}'",
            redirect_uri, client_id
        );
        return render_invalid_redirect_uri_error(&state.tera);
    }

    let client_state = query.state.clone();

    if query.scope.is_none() {
        debug!("Missing scope");
        return missing_parameter(
            redirect_uri,
            ProtocolError::InvalidRequest,
            "Missing required parameter scope",
            &client_state,
        );
    }

    if query.response_type.is_none() {
        debug!("Missing response_type");
        return missing_parameter(
            redirect_uri,
            ProtocolError::InvalidRequest,
            "Missing required parameter response_type",
            &client_state,
        );
    }

    if let Err(e) = session.set(SESSION_KEY, serde_urlencoded::to_string(query.0).unwrap()) {
        error!("Failed to serialise session: {}", e);
        return server_error(&state.tera);
    }

    HttpResponse::SeeOther()
        .set_header("Location", "authenticate")
        .finish()
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

pub fn missing_parameter(
    redirect_uri: &str,
    error: ProtocolError,
    description: &str,
    state: &Option<String>,
) -> HttpResponse {
    let mut url = Url::parse(redirect_uri).expect("should have been validated upon registration");

    url.query_pairs_mut()
        .append_pair("error", &format!("{}", error))
        .append_pair("error_description", description);

    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }

    HttpResponse::TemporaryRedirect()
        .set_header("Location", url.as_str())
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_session::UserSession;
    use actix_web::http;
    use actix_web::test;
    use actix_web::web::Data;
    use actix_web::web::Query;

    use url::Url;

    use crate::http::state::tests::build_test_state;
    use crate::store::tests::CONFIDENTIAL_CLIENT;
    use crate::store::tests::UNKNOWN_CLIENT_ID;

    #[actix_rt::test]
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
        let state = Data::new(build_test_state());

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
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
        let state = Data::new(build_test_state());

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
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
        let state = Data::new(build_test_state());

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
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
        let state = Data::new(build_test_state());

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn missing_scope_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let state = Data::new(build_test_state());
        let redirect_uri = state
            .client_store
            .get(CONFIDENTIAL_CLIENT)
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let query = Query(Request {
            scope: None,
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

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::TEMPORARY_REDIRECT);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(&redirect_uri).unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());
        let expected_error = format!("{}", ProtocolError::InvalidRequest);
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[actix_rt::test]
    async fn missing_response_type_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let state = Data::new(build_test_state());
        let redirect_uri = state
            .client_store
            .get(CONFIDENTIAL_CLIENT)
            .unwrap()
            .redirect_uris[0]
            .to_string();
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

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::TEMPORARY_REDIRECT);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(&redirect_uri).unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());
        let expected_error = format!("{}", ProtocolError::InvalidRequest);
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[actix_rt::test]
    async fn successful_authorization_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let state = Data::new(build_test_state());
        let redirect_uri = state
            .client_store
            .get(CONFIDENTIAL_CLIENT)
            .unwrap()
            .redirect_uris[0]
            .to_string();
        let client_state = "somestate".to_string();
        let request = Request {
            scope: Some("email".to_string()),
            response_type: Some(ResponseType::Code),
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

        let resp = post(query, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);

        let session = req.get_session();
        let first_request = session.get::<String>(SESSION_KEY).unwrap().unwrap();
        let first_request = serde_urlencoded::from_str::<Request>(&first_request).unwrap();
        assert_eq!(request, first_request);
    }
}
