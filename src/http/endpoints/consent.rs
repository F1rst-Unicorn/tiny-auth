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

use super::render_template;
use super::server_error;
use crate::http::endpoints::authenticate;
use crate::http::endpoints::authorize;
use crate::http::state::State;

use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use url::Url;

use chrono::offset::Local;

use log::debug;
use log::error;

pub async fn get(state: web::Data<State>, session: Session) -> HttpResponse {
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!(
            "Unsolicited consent request. authorize request was {:?}",
            first_request
        );
        return render_invalid_consent_request(&state.tera);
    }

    let authenticated = session.get::<String>(authenticate::SESSION_KEY);
    if authenticated.is_err() || authenticated.as_ref().unwrap().is_none() {
        debug!(
            "Unsolicited consent request. authenticate request was {:?}",
            authenticated
        );
        return render_invalid_consent_request(&state.tera);
    }

    render_template("consent.html.j2", StatusCode::OK, &state.tera)
}

pub async fn post(session: Session, state: web::Data<State>) -> HttpResponse {
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited consent request. {:?}", first_request);
        return render_invalid_consent_request(&state.tera);
    }

    let username = session.get::<String>(authenticate::SESSION_KEY);
    if username.is_err() || username.as_ref().unwrap().is_none() {
        debug!("Unsolicited consent request. {:?}", username);
        return render_invalid_consent_request(&state.tera);
    }
    let username = username.unwrap().unwrap();

    let first_request_result =
        serde_urlencoded::from_str::<authorize::Request>(&first_request.unwrap().unwrap());

    if let Err(e) = first_request_result {
        error!("Failed to deserialize initial request. {}", e);
        return server_error(&state.tera);
    }

    let first_request = first_request_result.unwrap();
    let redirect_uri = first_request.redirect_uri.unwrap();
    let mut url = Url::parse(&redirect_uri).expect("should have been validated upon registration");

    let code = state.auth_code_store.get_authorization_code(
        first_request.client_id.as_ref().unwrap(),
        &username,
        &redirect_uri,
        Local::now(),
    );

    url.query_pairs_mut().append_pair("code", &code);

    if let Some(state) = first_request.state {
        url.query_pairs_mut().append_pair("state", &state);
    }

    HttpResponse::Found()
        .set_header("Location", url.as_str())
        .finish()
}

pub fn render_invalid_consent_request(tera: &tera::Tera) -> HttpResponse {
    render_template(
        "invalid_consent_request.html.j2",
        StatusCode::BAD_REQUEST,
        tera,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_session::UserSession;
    use actix_web::http;
    use actix_web::test;
    use actix_web::web::Data;

    use crate::http::state::tests::build_test_state;
    use crate::store::tests::PUBLIC_CLIENT;

    #[actix_rt::test]
    async fn empty_session_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();

        let resp = get(state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn missing_authentication_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session.set(authorize::SESSION_KEY, "dummy").unwrap();

        let resp = get(state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn valid_request_is_rendered() {
        let req = test::TestRequest::get().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session.set(authorize::SESSION_KEY, "dummy").unwrap();
        session.set(authenticate::SESSION_KEY, "user").unwrap();

        let resp = get(state, session).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn posting_empty_session_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();

        let resp = post(session, state).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn posting_missing_authentication_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session.set(authorize::SESSION_KEY, "dummy").unwrap();

        let resp = post(session, state).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn successful_request_is_forwarded() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some("http://localhost/".to_string()),
            state: Some("state".to_string()),
            acr_values: None,
            display: None,
            id_token_hint: None,
            login_hint: None,
            nonce: None,
            max_age: None,
            prompt: None,
            response_mode: None,
            response_type: None,
            scope: None,
            ui_locales: None,
        };
        session
            .set(
                authorize::SESSION_KEY,
                &serde_urlencoded::to_string(first_request.clone()).unwrap(),
            )
            .unwrap();
        session.set(authenticate::SESSION_KEY, "user").unwrap();

        let resp = post(session, state).await;

        assert_eq!(resp.status(), http::StatusCode::FOUND);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(first_request.redirect_uri.as_ref().unwrap()).unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param.0 == "state".to_string()
                && &param.1 == first_request.state.as_ref().unwrap()));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param.0 == "code".to_string() && !param.1.is_empty()));
    }
}
