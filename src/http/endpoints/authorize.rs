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

use crate::http::endpoints::missing_parameter;
use crate::http::endpoints::server_error;
use crate::http::state;
use crate::protocol::oauth2::ProtocolError;
use crate::protocol::oauth2::ResponseType;

use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use serde_derive::Deserialize;
use serde_derive::Serialize;

use tera::Context;
use tera::Tera;

use log::debug;
use log::error;
use log::info;

pub const SESSION_KEY: &str = "a";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Request {
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    response_type: Option<ResponseType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    response_mode: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    display: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    prompt: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    max_age: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ui_locales: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    id_token_hint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    login_hint: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    acr_values: Option<String>,
}

impl Request {
    fn normalise(&mut self) {
        if self.scope.is_some() && self.scope.as_ref().unwrap().is_empty() {
            self.scope = None
        }
        if self.client_id.is_some() && self.client_id.as_ref().unwrap().is_empty() {
            self.client_id = None
        }
        if self.redirect_uri.is_some() && self.redirect_uri.as_ref().unwrap().is_empty() {
            self.redirect_uri = None
        }
        if self.state.is_some() && self.state.as_ref().unwrap().is_empty() {
            self.state = None
        }
        if self.response_mode.is_some() && self.response_mode.as_ref().unwrap().is_empty() {
            self.response_mode = None
        }
        if self.nonce.is_some() && self.nonce.as_ref().unwrap().is_empty() {
            self.nonce = None
        }
        if self.display.is_some() && self.display.as_ref().unwrap().is_empty() {
            self.display = None
        }
        if self.prompt.is_some() && self.prompt.as_ref().unwrap().is_empty() {
            self.prompt = None
        }
        if self.max_age.is_some() && self.max_age.as_ref().unwrap().is_empty() {
            self.max_age = None
        }
        if self.ui_locales.is_some() && self.ui_locales.as_ref().unwrap().is_empty() {
            self.ui_locales = None
        }
        if self.id_token_hint.is_some() && self.id_token_hint.as_ref().unwrap().is_empty() {
            self.id_token_hint = None
        }
        if self.login_hint.is_some() && self.login_hint.as_ref().unwrap().is_empty() {
            self.login_hint = None
        }
        if self.acr_values.is_some() && self.acr_values.as_ref().unwrap().is_empty() {
            self.acr_values = None
        }
    }
}

pub async fn get(
    query: web::Query<Request>,
    state: web::Data<state::State>,
    session: Session,
) -> HttpResponse {
    post(query, state, session).await
}

pub async fn post(
    mut query: web::Query<Request>,
    state: web::Data<state::State>,
    session: Session,
) -> HttpResponse {
    query.normalise();

    if query.client_id.is_none() {
        debug!("missing client_id");
        return render_invalid_client_id_error(&state.tera);
    }

    if query.redirect_uri.is_none() {
        debug!("missing redirect_uri");
        return render_invalid_redirect_uri_error(&state.tera);
    }

    let redirect_uri = query.redirect_uri.clone().unwrap();
    let client_id = query.client_id.as_ref().unwrap();

    let client = state.client_store.get(client_id);

    if client.is_none() {
        info!("client '{}' not found", client_id);
        return render_invalid_client_id_error(&state.tera);
    }
    let client = client.expect("checked before");

    if !client.is_redirect_uri_valid(&redirect_uri) {
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
            &redirect_uri,
            ProtocolError::InvalidRequest,
            &format!("Missing required parameter scope"),
            &client_state,
        );
    }

    if query.response_type.is_none() {
        debug!("Missing response_type");
        return missing_parameter(
            &redirect_uri,
            ProtocolError::InvalidRequest,
            &format!("Missing required parameter response_type"),
            &client_state,
        );
    }

    if let Err(e) = session.set(SESSION_KEY, serde_urlencoded::to_string(query.0).unwrap()) {
        error!("Failed to serialise session: {}", e);
        return missing_parameter(
            &redirect_uri,
            ProtocolError::ServerError,
            "session serialisation failed",
            &client_state,
        );
    }

    HttpResponse::SeeOther()
        .set_header("Location", "authenticate")
        .finish()
}

fn render_invalid_client_id_error(tera: &Tera) -> HttpResponse {
    let body = tera.render("invalid_client_id.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::BadRequest()
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", e);
            server_error(tera)
        }
    }
}

fn render_invalid_redirect_uri_error(tera: &Tera) -> HttpResponse {
    let body = tera.render("invalid_redirect_uri.html.j2", &Context::new());
    match body {
        Ok(body) => HttpResponse::BadRequest()
            .set_header("Content-Type", "text/html")
            .body(body),
        Err(e) => {
            log::warn!("{}", e);
            server_error(tera)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http;
    use actix_web::test;
    use actix_web::web::Data;
    use actix_web::web::Query;
    use actix_session::UserSession;

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
        let redirect_uri = state.client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
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
        assert!(url.query_pairs().into_owned().any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url.query_pairs().into_owned().any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[actix_rt::test]
    async fn missing_response_type_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let state = Data::new(build_test_state());
        let redirect_uri = state.client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
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
        assert!(url.query_pairs().into_owned().any(|param| param == ("state".to_string(), client_state.to_string())));
        assert!(url.query_pairs().into_owned().any(|param| param == ("error".to_string(), expected_error.to_string())));
    }

    #[actix_rt::test]
    async fn successful_authorization_is_redirected() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let state = Data::new(build_test_state());
        let redirect_uri = state.client_store.get(CONFIDENTIAL_CLIENT).unwrap().redirect_uris[0].to_string();
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