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
use crate::business::authenticator::Authenticator;
use crate::http::endpoints::authorize;
use crate::http::endpoints::render_template_with_context;
use crate::protocol::oauth2;
use crate::protocol::oidc;

use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use url::Url;

use tera::Context;
use tera::Tera;

use log::debug;
use log::error;
use log::warn;

use serde_derive::Deserialize;
use serde_derive::Serialize;

pub const SESSION_KEY: &str = "b";
const ERROR_CODE_SESSION_KEY: &str = "e";
const TRIES_LEFT_SESSION_KEY: &str = "t";

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

pub async fn get(session: Session, tera: web::Data<Tera>) -> HttpResponse {
    match session.get::<String>(authorize::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited authentication request");
            return render_invalid_authentication_request(&tera);
        }
        _ => {}
    }

    match build_context(&session) {
        Some(context) => {
            render_template_with_context("authenticate.html.j2", StatusCode::OK, &tera, &context)
        }
        None => server_error(&tera),
    }
}

pub async fn post(
    query: web::Form<Request>,
    session: Session,
    tera: web::Data<Tera>,
    authenticator: web::Data<Authenticator>,
) -> HttpResponse {
    session.remove(ERROR_CODE_SESSION_KEY);

    if !super::is_csrf_valid(&query.csrftoken, &session) {
        debug!("CSRF protection violation detected");
        return render_invalid_authentication_request(&tera);
    }

    match session.get::<String>(authorize::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited authentication request");
            return render_invalid_authentication_request(&tera);
        }
        _ => {}
    }

    let tries_left = match session.get::<i32>(TRIES_LEFT_SESSION_KEY) {
        Err(_) => {
            debug!("unsolicited authentication request");
            return render_invalid_authentication_request(&tera);
        }
        Ok(None) => 2,
        Ok(Some(tries)) => tries - 1,
    };

    let username = if query.username.is_none() {
        debug!("missing username");
        return render_invalid_input(1, &tera, &session, None);
    } else {
        query.username.clone().unwrap()
    };

    let password = if query.password.is_none() {
        debug!("missing password");
        return render_invalid_input(2, &tera, &session, None);
    } else {
        query.password.clone().unwrap()
    };

    if authenticator.authenticate_user(&username, &password) {
        session.remove(TRIES_LEFT_SESSION_KEY);
        session.remove(ERROR_CODE_SESSION_KEY);
        redirect_successfully(&tera, &session, &username)
    } else if tries_left > 0 {
        debug!("{} tries left", tries_left);
        render_invalid_input(3, &tera, &session, Some(tries_left))
    } else {
        debug!("no tries left");
        session.remove(TRIES_LEFT_SESSION_KEY);
        session.remove(ERROR_CODE_SESSION_KEY);
        render_redirect_error(
            session,
            &tera,
            oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
            "user failed to authenticate",
        )
    }
}

pub async fn cancel(session: Session, tera: web::Data<Tera>) -> HttpResponse {
    render_redirect_error(
        session,
        &tera,
        oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
        "user denied authentication",
    )
}

fn render_redirect_error(
    session: Session,
    tera: &Tera,
    error: oidc::ProtocolError,
    description: &str,
) -> HttpResponse {
    let first_request = match session.get::<String>(authorize::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited authentication request");
            return render_invalid_authentication_request(&tera);
        }
        Ok(Some(req)) => req,
    };
    let first_request = match serde_urlencoded::from_str::<authorize::Request>(&first_request) {
        Err(e) => {
            error!("Failed to deserialize initial request. {}", e);
            return server_error(&tera);
        }
        Ok(req) => req,
    };

    let redirect_uri = first_request.redirect_uri.unwrap();
    let mut url = Url::parse(&redirect_uri).expect("should have been validated upon registration");

    super::render_redirect_error(&mut url, error, description)
}

fn build_context(session: &Session) -> Option<Context> {
    let mut context = Context::new();
    if let Ok(Some(error_code)) = session.get::<u64>(ERROR_CODE_SESSION_KEY) {
        context.insert(super::ERROR_CONTEXT, &error_code);
    }

    if let Ok(Some(tries_left)) = session.get::<u64>(TRIES_LEFT_SESSION_KEY) {
        context.insert(super::TRIES_LEFT_CONTEXT, &tries_left);
    }

    let csrftoken = super::generate_csrf_token();
    context.insert(super::CSRF_CONTEXT, &csrftoken);

    if let Err(e) = session.set(super::CSRF_SESSION_KEY, csrftoken) {
        warn!("Failed to construct context: {}", e);
        return None;
    }
    Some(context)
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

fn render_invalid_input(
    error: u64,
    tera: &Tera,
    session: &Session,
    tries_left: Option<i32>,
) -> HttpResponse {
    if let Err(e) = session.set(ERROR_CODE_SESSION_KEY, error) {
        error!("Failed to serialise session: {}", e);
        return server_error(tera);
    }

    if let Some(tries_left) = tries_left {
        if let Err(e) = session.set(TRIES_LEFT_SESSION_KEY, tries_left) {
            error!("Failed to serialise session: {}", e);
            return server_error(tera);
        }
    }

    HttpResponse::SeeOther()
        .set_header("Location", "authenticate")
        .finish()
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
    use actix_web::web::Form;

    use super::super::generate_csrf_token;
    use super::super::CSRF_SESSION_KEY;
    use crate::http::state::tests::build_test_authenticator;
    use crate::http::state::tests::build_test_tera;
    use crate::store::tests::UNKNOWN_USER;
    use crate::store::tests::USER;

    #[actix_rt::test]
    async fn empty_session_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn authorization_in_session_gives_login_form() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .set(authorize::SESSION_KEY, "dummy".to_string())
            .unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn missing_csrf_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let form = Form(Request {
            username: Some("user".to_string()),
            password: Some("user".to_string()),
            csrftoken: None,
        });

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn emtpy_session_login_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let form = Form(Request {
            username: Some("user".to_string()),
            password: Some("user".to_string()),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn missing_username_gives_error() {
        let req = test::TestRequest::post().to_http_request();
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

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;
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

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;
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

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;
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

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;
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

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;
        let session = req.get_session();

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert_eq!("consent", url);
        assert_eq!(session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap(), None);
        assert_eq!(session.get::<String>(SESSION_KEY).unwrap().unwrap(), USER);
    }
}
