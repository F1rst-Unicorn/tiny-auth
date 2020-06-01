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
use super::server_error;
use crate::http::endpoints::{authorize, render_template_with_context};
use crate::http::state::State;

use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use tera::Context;
use tera::Tera;

use log::debug;
use log::error;
use log::warn;

use serde_derive::Deserialize;
use serde_derive::Serialize;

pub const SESSION_KEY: &str = "b";
const ERROR_CODE_SESSION_KEY: &str = "e";

#[derive(Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    username: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    password: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    csrftoken: Option<String>,
}

pub async fn get(state: web::Data<State>, session: Session) -> HttpResponse {
    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited authentication request. {:?}", first_request);
        return render_invalid_authentication_request(&state.tera);
    }

    let context = build_context(&session);
    match context {
        Some(context) => render_template_with_context(
            "authenticate.html.j2",
            StatusCode::OK,
            &state.tera,
            &context,
        ),
        None => server_error(&state.tera),
    }
}

fn build_context(session: &Session) -> Option<Context> {
    let mut context = Context::new();
    if let Some(error_code) = session
        .get::<u64>(ERROR_CODE_SESSION_KEY)
        .expect("failed to deserialize")
    {
        context.insert(super::ERROR_CONTEXT, &error_code);
    }

    let csrftoken = super::generate_csrf_token();
    context.insert(super::CSRF_CONTEXT, &csrftoken);

    if let Err(e) = session.set(super::CSRF_SESSION_KEY, csrftoken) {
        warn!("Failed to construct context: {}", e);
        return None;
    }
    Some(context)
}

pub async fn post(
    query: web::Form<Request>,
    state: web::Data<State>,
    session: Session,
) -> HttpResponse {
    session.remove(ERROR_CODE_SESSION_KEY);

    if !super::is_csrf_valid(&query.csrftoken, &session) {
        debug!("CSRF protection violation detected");
        return render_invalid_authentication_request(&state.tera);
    }

    let first_request = session.get::<String>(authorize::SESSION_KEY);
    if first_request.is_err() || first_request.as_ref().unwrap().is_none() {
        debug!("Unsolicited authentication request. {:?}", first_request);
        return render_invalid_authentication_request(&state.tera);
    }

    if query.username.is_none() {
        debug!("missing username");
        return render_invalid_input(1, &state.tera, &session);
    }

    if query.password.is_none() {
        debug!("missing password");
        return render_invalid_input(2, &state.tera, &session);
    }

    let username = query.username.clone().expect("checked before");
    let user = state.user_store.get(&username);

    if user.is_none() {
        debug!("user '{}' not found", username);
        return render_invalid_input(3, &state.tera, &session);
    }

    let user = user.expect("checked before");
    let password = query.password.clone().expect("checked before");

    if user.is_password_correct(&password) {
        redirect_successfully(&state.tera, &session, &user.name)
    } else {
        debug!("password of user '{}' wrong", username);
        render_invalid_input(3, &state.tera, &session)
    }
}

fn redirect_successfully(tera: &Tera, session: &Session, user: &str) -> HttpResponse {
    if let Err(e) = session.set(SESSION_KEY, user) {
        error!("Failed to serialise session: {}", e);
        return server_error(tera);
    }
    HttpResponse::SeeOther()
        .set_header("Location", "consent")
        .finish()
}

fn render_invalid_input(error: u64, tera: &Tera, session: &Session) -> HttpResponse {
    if let Err(e) = session.set(ERROR_CODE_SESSION_KEY, error) {
        error!("Failed to serialise session: {}", e);
        server_error(tera)
    } else {
        HttpResponse::SeeOther()
            .set_header("Location", "authenticate")
            .finish()
    }
}

fn render_invalid_authentication_request(tera: &Tera) -> HttpResponse {
    render_template(
        "invalid_authentication_request.html.j2",
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
    use actix_web::web::Form;

    use super::super::generate_csrf_token;
    use super::super::CSRF_SESSION_KEY;
    use crate::http::state::tests::build_test_state;
    use crate::store::tests::UNKNOWN_USER;
    use crate::store::tests::USER;

    #[actix_rt::test]
    async fn empty_session_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();

        let resp = get(state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn authorization_in_session_gives_login_form() {
        let req = test::TestRequest::get().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();

        let resp = get(state, session).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn missing_csrf_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        let form = Form(Request {
            username: Some("user".to_string()),
            password: Some("user".to_string()),
            csrftoken: None,
        });

        let resp = post(form, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn emtpy_session_login_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let form = Form(Request {
            username: Some("user".to_string()),
            password: Some("user".to_string()),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, state, session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn missing_username_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: None,
            password: Some("user".to_string()),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, state, session).await;
        let session = req.get_session();

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);
        assert_eq!(
            session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
            1
        );
    }

    #[actix_rt::test]
    async fn missing_password_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: Some("user".to_string()),
            password: None,
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, state, session).await;
        let session = req.get_session();

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);
        assert_eq!(
            session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
            2
        );
    }

    #[actix_rt::test]
    async fn unknown_user_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: Some(UNKNOWN_USER.to_string()),
            password: Some(UNKNOWN_USER.to_string() + "wrong"),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, state, session).await;
        let session = req.get_session();

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);
        assert_eq!(
            session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
            3
        );
    }

    #[actix_rt::test]
    async fn wrong_password_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: Some(USER.to_string()),
            password: Some(USER.to_string() + "wrong"),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, state, session).await;
        let session = req.get_session();

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("authenticate", url);
        assert_eq!(
            session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
            3
        );
    }

    #[actix_rt::test]
    async fn correct_login_is_reported() {
        let req = test::TestRequest::post().to_http_request();
        let state = Data::new(build_test_state());
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, state, session).await;
        let session = req.get_session();

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("consent", url);
        assert_eq!(session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap(), None);
        assert_eq!(session.get::<String>(SESSION_KEY).unwrap().unwrap(), USER);
    }
}
