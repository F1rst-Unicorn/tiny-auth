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
use crate::endpoints::parse_first_request;
use crate::endpoints::render_template_with_context;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use chrono::Local;
use log::debug;
use log::error;
use log::warn;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tera::Context;
use tera::Tera;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::authenticator::Error;
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc;
use tiny_auth_business::oidc::Prompt;
use tiny_auth_business::serde::deserialise_empty_as_none;

pub const SESSION_KEY: &str = "b";
pub const AUTH_TIME_SESSION_KEY: &str = "t";
const ERROR_CODE_SESSION_KEY: &str = "e";
const TRIES_LEFT_SESSION_KEY: &str = "l";

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
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(&tera);
        }
        Some(req) => req,
    };

    if let Ok(Some(username)) = session.get::<String>(SESSION_KEY) {
        if first_request.prompts.contains(&Prompt::Login)
            || first_request.prompts.contains(&Prompt::SelectAccount)
        {
            debug!("Recognised user '{}' but client demands login", username);
            render_login_form(session, tera)
        } else if let Some(max_age) = first_request.max_age {
            let auth_time = match session.get::<i64>(AUTH_TIME_SESSION_KEY) {
                Err(_) | Ok(None) => {
                    debug!("unsolicited authentication request, missing auth_time but username was present");
                    return render_invalid_authentication_request(&tera);
                }
                Ok(Some(v)) => v,
            };
            let now = Local::now();
            if now.timestamp() - auth_time <= max_age {
                debug!(
                    "Recognised authenticated user '{}' and max_age is still ok",
                    username
                );
                redirect_successfully()
            } else {
                debug!(
                    "Recognised authenticated user '{}' but client demands more recent login",
                    username
                );
                render_login_form(session, tera)
            }
        } else {
            debug!("Recognised authenticated user '{}'", username);
            redirect_successfully()
        }
    } else if first_request.prompts.contains(&Prompt::None) {
        debug!("No user recognised but client demands no interaction");
        render_redirect_error(
            session,
            &tera,
            oidc::ProtocolError::Oidc(oidc::OidcProtocolError::LoginRequired),
            "No username found",
            first_request.encode_redirect_to_fragment,
        )
    } else {
        render_login_form(session, tera)
    }
}

fn render_login_form(session: Session, tera: web::Data<Tera>) -> HttpResponse {
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

    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(&tera);
        }
        Some(req) => req,
    };

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
        return render_invalid_login_attempt_error(1, &tera, &session, None);
    } else {
        query.username.clone().unwrap()
    };

    let password = if query.password.is_none() {
        debug!("missing password");
        return render_invalid_login_attempt_error(2, &tera, &session, None);
    } else {
        query.password.clone().unwrap()
    };

    let auth_result = authenticator
        .authenticate_user_and_forget(&username, &password)
        .await;

    if auth_result.is_ok() {
        session.remove(TRIES_LEFT_SESSION_KEY);
        session.remove(ERROR_CODE_SESSION_KEY);
        if let Err(e) = session.insert(SESSION_KEY, &username) {
            error!("Failed to serialise session: {}", e);
            return server_error(&tera);
        }
        if let Err(e) = session.insert(AUTH_TIME_SESSION_KEY, Local::now().timestamp()) {
            error!("Failed to serialise auth_time: {}", e);
            return server_error(&tera);
        }
        redirect_successfully()
    } else if let Err(Error::RateLimited) = auth_result {
        render_invalid_login_attempt_error(4, &tera, &session, None)
    } else if tries_left > 0 {
        debug!("{} tries left", tries_left);
        render_invalid_login_attempt_error(3, &tera, &session, Some(tries_left))
    } else {
        debug!("no tries left");
        session.remove(TRIES_LEFT_SESSION_KEY);
        session.remove(ERROR_CODE_SESSION_KEY);
        render_redirect_error(
            session,
            &tera,
            oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
            "user failed to authenticate",
            first_request.encode_redirect_to_fragment,
        )
    }
}

pub async fn cancel(session: Session, tera: web::Data<Tera>) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(&tera);
        }
        Some(req) => req,
    };

    render_redirect_error(
        session,
        &tera,
        oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
        "user denied authentication",
        first_request.encode_redirect_to_fragment,
    )
}

pub async fn select_account(session: Session) -> HttpResponse {
    session.remove(SESSION_KEY);
    session.remove(AUTH_TIME_SESSION_KEY);

    HttpResponse::SeeOther()
        .insert_header(("Location", "authenticate"))
        .finish()
}

fn render_redirect_error(
    session: Session,
    tera: &Tera,
    error: oidc::ProtocolError,
    description: &str,
    encode_to_fragment: bool,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(tera);
        }
        Some(req) => req,
    };

    super::render_redirect_error(
        &first_request.redirect_uri,
        error,
        description,
        &first_request.state,
        encode_to_fragment,
    )
}

fn build_context(session: &Session) -> Option<Context> {
    let mut context = Context::new();
    if let Ok(Some(error_code)) = session.get::<u64>(ERROR_CODE_SESSION_KEY) {
        context.insert(super::ERROR_CONTEXT, &error_code);
    }

    if let Ok(Some(tries_left)) = session.get::<u64>(TRIES_LEFT_SESSION_KEY) {
        context.insert(super::TRIES_LEFT_CONTEXT, &tries_left);
    }

    let first_request = parse_first_request(session)?;
    if let Some(login_hint) = first_request.login_hint {
        context.insert(super::LOGIN_HINT_CONTEXT, &login_hint);
    }

    let csrftoken = super::generate_csrf_token();
    context.insert(super::CSRF_CONTEXT, &csrftoken);

    if let Err(e) = session.insert(super::CSRF_SESSION_KEY, csrftoken) {
        warn!("Failed to construct context: {}", e);
        return None;
    }
    Some(context)
}

fn redirect_successfully() -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header(("Location", "consent"))
        .finish()
}

fn render_invalid_login_attempt_error(
    error: u64,
    tera: &Tera,
    session: &Session,
    tries_left: Option<i32>,
) -> HttpResponse {
    if let Err(e) = session.insert(ERROR_CODE_SESSION_KEY, error) {
        error!("Failed to serialise session: {}", e);
        return server_error(tera);
    }

    if let Some(tries_left) = tries_left {
        if let Err(e) = session.insert(TRIES_LEFT_SESSION_KEY, tries_left) {
            error!("Failed to serialise session: {}", e);
            return server_error(tera);
        }
    }

    HttpResponse::SeeOther()
        .insert_header(("Location", "authenticate"))
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
    use super::super::generate_csrf_token;
    use super::super::CSRF_SESSION_KEY;
    use super::*;
    use crate::endpoints::authorize;
    use crate::endpoints::tests::build_test_authenticator;
    use crate::endpoints::tests::build_test_tera;
    use actix_session::SessionExt;
    use actix_web::http;
    use actix_web::test;
    use actix_web::web::Form;
    use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
    use tiny_auth_business::oidc::ResponseType;
    use tiny_auth_business::store::test_fixtures::UNKNOWN_USER;
    use tiny_auth_business::store::test_fixtures::USER;
    use url::Url;

    #[test_log::test(actix_web::test)]
    async fn empty_session_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn authorization_in_session_gives_login_form() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[test_log::test(actix_web::test)]
    async fn recognising_user_redirects_to_consent() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        session.insert(SESSION_KEY, "dummy").unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::SEE_OTHER);
    }

    #[test_log::test(actix_web::test)]
    async fn recognising_user_but_login_demanded_gives_form() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    prompts: vec![Prompt::Login],
                    ..Default::default()
                },
            )
            .unwrap();
        session.insert(SESSION_KEY, "dummy").unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[test_log::test(actix_web::test)]
    async fn recognising_user_but_account_selection_demanded_gives_form() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    prompts: vec![Prompt::SelectAccount],
                    ..Default::default()
                },
            )
            .unwrap();
        session.insert(SESSION_KEY, "dummy").unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[test_log::test(actix_web::test)]
    async fn no_user_recognised_but_no_prompt_demanded_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    prompts: vec![Prompt::None],
                    response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                    redirect_uri: "http://localhost/public".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::FOUND);
    }

    #[test_log::test(actix_web::test)]
    async fn user_recognised_but_login_too_old_gives_login_form() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    max_age: Some(0),
                    ..Default::default()
                },
            )
            .unwrap();
        session.insert(SESSION_KEY, "dummy").unwrap();
        session
            .insert(AUTH_TIME_SESSION_KEY, Local::now().timestamp() - 1)
            .unwrap();

        let resp = get(session, build_test_tera()).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[test_log::test(actix_web::test)]
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

    #[test_log::test(actix_web::test)]
    async fn emtpy_session_login_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let form = Form(Request {
            username: Some("user".to_string()),
            password: Some("user".to_string()),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn missing_username_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

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

    #[test_log::test(actix_web::test)]
    async fn missing_password_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

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

    #[test_log::test(actix_web::test)]
    async fn unknown_user_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

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

    #[test_log::test(actix_web::test)]
    async fn wrong_password_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

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

    #[test_log::test(actix_web::test)]
    async fn correct_login_is_reported() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

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

    #[test_log::test(actix_web::test)]
    async fn default_try_count_is_two() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: Some(UNKNOWN_USER.to_string()),
            password: Some(UNKNOWN_USER.to_string()),
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
        assert_eq!(
            session.get::<i32>(TRIES_LEFT_SESSION_KEY).unwrap().unwrap(),
            2
        );
    }

    #[test_log::test(actix_web::test)]
    async fn no_tries_left_will_redirect_to_client() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    redirect_uri: "http://redirect_uri.example".to_string(),
                    response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                    ..Default::default()
                },
            )
            .unwrap();
        session.insert(TRIES_LEFT_SESSION_KEY, 1).unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

        let form = Form(Request {
            username: Some(UNKNOWN_USER.to_string()),
            password: Some(UNKNOWN_USER.to_string()),
            csrftoken: Some(csrftoken),
        });

        let resp = post(form, session, build_test_tera(), build_test_authenticator()).await;

        assert_eq!(resp.status(), http::StatusCode::FOUND);
        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param.0 == "error".to_string()
                && param.1
                    == format!(
                        "{}",
                        oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied)
                    )));
        assert!(url
            .query_pairs()
            .into_owned()
            .any(|param| param.0 == "error_description".to_string()
                && param.1 == "user failed to authenticate"));
    }
}
