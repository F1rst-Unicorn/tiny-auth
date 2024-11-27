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

use super::{authenticate, consent, error_with_code, return_rendered_template, server_error};
use crate::endpoints::parse_first_request;
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use chrono::Local;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::authenticator::Error;
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc;
use tiny_auth_business::oidc::Prompt;
use tiny_auth_business::serde::deserialise_empty_as_none;
use tiny_auth_business::template::web::AuthenticateError::{
    MissingPassword, MissingUsername, RateLimit, WrongCredentials,
};
use tiny_auth_business::template::web::ErrorPage::ServerError;
use tiny_auth_business::template::web::{
    AuthenticateContext, AuthenticateError, ErrorPage, WebTemplater,
};
use tracing::{debug, instrument};
use tracing::{error, span, Level};
use tracing::{warn, Instrument};
use web::Data;

pub const ENDPOINT_NAME: &str = "authenticate";

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

#[instrument(skip_all, name = "authenticate_get")]
pub async fn get(
    session: Session,
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(templater);
        }
        Some(req) => req,
    };
    let _flow_guard = span!(
        Level::DEBUG,
        "flow",
        state = first_request.state,
        nonce = first_request.nonce
    )
    .entered();

    if let Ok(Some(username)) = session.get::<String>(SESSION_KEY) {
        let _cid_guard = span!(Level::DEBUG, "cid", user = username).entered();
        if first_request.prompts.contains(&Prompt::Login)
            || first_request.prompts.contains(&Prompt::SelectAccount)
        {
            debug!("recognised user but client demands login");
            render_login_form(session, templater)
        } else if let Some(max_age) = first_request.max_age {
            let auth_time = match session.get::<i64>(AUTH_TIME_SESSION_KEY) {
                Err(e) => {
                    debug!(%e, "unsolicited authentication request, missing auth_time but username was present");
                    return render_invalid_authentication_request(templater);
                }
                Ok(None) => {
                    debug!("unsolicited authentication request, missing auth_time but username was present");
                    return render_invalid_authentication_request(templater);
                }
                Ok(Some(v)) => v,
            };
            let now = Local::now();
            if now.timestamp() - auth_time <= max_age {
                debug!("recognised authenticated user and max_age is still ok",);
                redirect_successfully()
            } else {
                debug!("recognised authenticated user but client demands more recent login",);
                render_login_form(session, templater)
            }
        } else {
            debug!("recognised authenticated user",);
            redirect_successfully()
        }
    } else if first_request.prompts.contains(&Prompt::None) {
        debug!("no user recognised but client demands no interaction");
        render_redirect_error(
            session,
            templater,
            oidc::ProtocolError::Oidc(oidc::OidcProtocolError::LoginRequired),
            "No username found",
            first_request.encode_redirect_to_fragment,
        )
    } else {
        render_login_form(session, templater)
    }
}

fn render_login_form(
    session: Session,
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
) -> HttpResponse {
    match build_context(&session) {
        Some(context) => {
            return_rendered_template(templater.instantiate(context), StatusCode::OK, || {
                templater.instantiate_error_page(ServerError)
            })
        }
        None => server_error(templater.instantiate_error_page(ServerError)),
    }
}

#[instrument(skip_all, name = "authenticate_post")]
pub async fn post(
    query: web::Form<Request>,
    session: Session,
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
    authenticator: Data<Authenticator>,
) -> HttpResponse {
    session.remove(ERROR_CODE_SESSION_KEY);

    if !super::is_csrf_valid(&query.csrftoken, &session) {
        debug!("CSRF protection violation detected");
        return render_invalid_authentication_request(templater);
    }

    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(templater);
        }
        Some(req) => req,
    };

    let flow = span!(
        Level::DEBUG,
        "flow",
        state = first_request.state,
        nonce = first_request.nonce
    );
    let flow_1 = flow.clone();
    let flow_guard = flow_1.enter();
    let tries_left = match session.get::<i32>(TRIES_LEFT_SESSION_KEY) {
        Err(e) => {
            debug!(%e, "unsolicited authentication request");
            return render_invalid_authentication_request(templater);
        }
        Ok(None) => 2,
        Ok(Some(tries)) => tries - 1,
    };

    let username = match &query.username {
        None => {
            debug!("missing username");
            return render_invalid_login_attempt_error(MissingUsername, templater, &session, None);
        }
        Some(v) => v,
    };

    let password = match &query.password {
        None => {
            debug!("missing password");
            return render_invalid_login_attempt_error(MissingPassword, templater, &session, None);
        }
        Some(v) => v,
    };

    drop(flow_guard);
    let auth_result = authenticator
        .authenticate_user_and_forget(username, password)
        .instrument(flow.clone())
        .await;

    let _flow_guard = flow.enter();
    match auth_result {
        Ok(_) => {
            session.remove(TRIES_LEFT_SESSION_KEY);
            session.remove(ERROR_CODE_SESSION_KEY);
            if let Err(e) = session.insert(SESSION_KEY, username) {
                error!(%e, "failed to serialise session");
                return server_error(templater.instantiate_error_page(ServerError));
            }
            if let Err(e) = session.insert(AUTH_TIME_SESSION_KEY, Local::now().timestamp()) {
                error!(%e, "failed to serialise auth_time");
                return server_error(templater.instantiate_error_page(ServerError));
            }
            redirect_successfully()
        }
        Err(Error::RateLimited) => {
            render_invalid_login_attempt_error(RateLimit, templater, &session, None)
        }
        Err(Error::WrongCredentials) if tries_left > 0 => {
            debug!(tries_left);
            render_invalid_login_attempt_error(
                WrongCredentials,
                templater,
                &session,
                Some(tries_left),
            )
        }
        Err(Error::WrongCredentials) => {
            debug!("no tries left");
            session.remove(TRIES_LEFT_SESSION_KEY);
            session.remove(ERROR_CODE_SESSION_KEY);
            render_redirect_error(
                session,
                templater,
                oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
                "user failed to authenticate",
                first_request.encode_redirect_to_fragment,
            )
        }
        Err(e) => {
            warn!(%e, "backend error");
            render_redirect_error(
                session,
                templater,
                oidc::ProtocolError::OAuth2(oauth2::ProtocolError::ServerError),
                "backend error",
                first_request.encode_redirect_to_fragment,
            )
        }
    }
}

#[instrument(skip_all, name = "authenticate_cancel")]
pub async fn cancel(
    session: Session,
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(templater);
        }
        Some(req) => req,
    };

    let _flow_guard = span!(
        Level::DEBUG,
        "flow",
        state = first_request.state,
        nonce = first_request.nonce
    )
    .entered();
    debug!("cancelling flow");
    render_redirect_error(
        session,
        templater,
        oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
        "user denied authentication",
        first_request.encode_redirect_to_fragment,
    )
}

#[instrument(skip_all, name = "authenticate_select_account")]
pub async fn select_account(session: Session) -> HttpResponse {
    debug!("selecting account");
    session.remove(SESSION_KEY);
    session.remove(AUTH_TIME_SESSION_KEY);

    HttpResponse::SeeOther()
        .insert_header((LOCATION, authenticate::ENDPOINT_NAME))
        .finish()
}

fn render_redirect_error(
    session: Session,
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
    error: oidc::ProtocolError,
    description: &str,
    encode_to_fragment: bool,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_authentication_request(templater);
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

fn build_context(session: &Session) -> Option<AuthenticateContext> {
    let error = session
        .get::<u8>(ERROR_CODE_SESSION_KEY)
        .ok()
        .flatten()
        .map(Into::into);
    let tries_left = session
        .get::<u64>(TRIES_LEFT_SESSION_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    let first_request = parse_first_request(session)?;
    let login_hint = first_request.login_hint.unwrap_or_default();
    let csrf_token = super::generate_csrf_token();

    if let Err(e) = session.insert(super::CSRF_SESSION_KEY, csrf_token.clone()) {
        warn!(%e, "failed to construct context");
        return None;
    }
    Some(AuthenticateContext {
        tries_left: error
            .as_ref()
            .filter(|v| **v == WrongCredentials)
            .map(|_| tries_left)
            .unwrap_or_default(),
        login_hint,
        error,
        csrf_token,
    })
}

fn redirect_successfully() -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((LOCATION, consent::ENDPOINT_NAME))
        .finish()
}

fn render_invalid_login_attempt_error(
    error: AuthenticateError,
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
    session: &Session,
    tries_left: Option<i32>,
) -> HttpResponse {
    if let Err(e) = session.insert::<u8>(ERROR_CODE_SESSION_KEY, error.into()) {
        error!(%e, "failed to serialise session");
        return server_error(templater.instantiate_error_page(ServerError));
    }

    if let Some(tries_left) = tries_left {
        if let Err(e) = session.insert(TRIES_LEFT_SESSION_KEY, tries_left) {
            error!(%e, "failed to serialise session");
            return server_error(templater.instantiate_error_page(ServerError));
        }
    }

    HttpResponse::SeeOther()
        .insert_header((LOCATION, authenticate::ENDPOINT_NAME))
        .finish()
}

fn render_invalid_authentication_request(
    templater: Data<dyn WebTemplater<AuthenticateContext>>,
) -> HttpResponse {
    error_with_code(
        templater.instantiate_error_page(ErrorPage::InvalidAuthenticationRequest),
        StatusCode::BAD_REQUEST,
    )
}

#[cfg(test)]
mod tests {
    use actix_web::web::Data;
    use std::sync::Arc;
    use tiny_auth_business::template::web::{AuthenticateContext, WebTemplater};
    use tiny_auth_test_fixtures::template::TestTemplater;

    mod get {
        use crate::endpoints::authenticate::tests::build_test_templater;
        use crate::endpoints::authenticate::{get, AUTH_TIME_SESSION_KEY, SESSION_KEY};
        use crate::endpoints::tests::query_parameter_of;
        use crate::endpoints::{authorize, consent, REDIRECT_QUERY_PARAM_ERROR};
        use actix_session::{Session, SessionExt};
        use actix_web::http::header::{HeaderValue, LOCATION};
        use actix_web::http::StatusCode;
        use actix_web::test::TestRequest;
        use chrono::Local;
        use pretty_assertions::assert_eq;
        use rstest::{fixture, rstest};
        use test_log::test;
        use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
        use tiny_auth_business::oauth2;
        use tiny_auth_business::oidc::OidcProtocolError::LoginRequired;
        use tiny_auth_business::oidc::{Prompt, ResponseType};
        use tiny_auth_test_fixtures::authorize_endpoint::test_request;
        use url::Url;

        #[rstest]
        #[test(actix_web::test)]
        async fn empty_session_gives_error(session: Session) {
            let resp = get(session, build_test_templater()).await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn authorization_in_session_gives_login_form(session: Session) {
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();

            let resp = get(session, build_test_templater()).await;

            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn recognising_user_redirects_to_consent(session: Session) {
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            session.insert(SESSION_KEY, "dummy").unwrap();

            let resp = get(session, build_test_templater()).await;

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            assert_eq!(
                resp.headers()
                    .get(LOCATION)
                    .map(HeaderValue::to_str)
                    .and_then(Result::ok),
                Some(consent::ENDPOINT_NAME)
            )
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn recognising_user_but_login_demanded_gives_form(session: Session) {
            session
                .insert(
                    authorize::SESSION_KEY,
                    AuthorizeRequestState {
                        prompts: vec![Prompt::Login],
                        ..test_request()
                    },
                )
                .unwrap();
            session.insert(SESSION_KEY, "dummy").unwrap();

            let resp = get(session, build_test_templater()).await;

            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn recognising_user_but_account_selection_demanded_gives_form(session: Session) {
            session
                .insert(
                    authorize::SESSION_KEY,
                    AuthorizeRequestState {
                        prompts: vec![Prompt::SelectAccount],
                        ..test_request()
                    },
                )
                .unwrap();
            session.insert(SESSION_KEY, "dummy").unwrap();

            let resp = get(session, build_test_templater()).await;

            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn no_user_recognised_but_no_prompt_demanded_gives_error(session: Session) {
            session
                .insert(
                    authorize::SESSION_KEY,
                    AuthorizeRequestState {
                        prompts: vec![Prompt::None],
                        response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                        ..test_request()
                    },
                )
                .unwrap();

            let resp = get(session, build_test_templater()).await;

            assert_eq!(StatusCode::FOUND, resp.status());
            let actual_redirect_uri = resp
                .headers()
                .get(LOCATION)
                .map(HeaderValue::to_str)
                .and_then(Result::ok)
                .map(Url::parse)
                .and_then(Result::ok)
                .unwrap();
            assert_eq!(
                Some(LoginRequired.to_string()),
                query_parameter_of(&actual_redirect_uri, REDIRECT_QUERY_PARAM_ERROR)
            );
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn user_recognised_but_login_too_old_gives_login_form(session: Session) {
            session
                .insert(
                    authorize::SESSION_KEY,
                    AuthorizeRequestState {
                        max_age: Some(0),
                        ..test_request()
                    },
                )
                .unwrap();
            session.insert(SESSION_KEY, "dummy").unwrap();
            session
                .insert(AUTH_TIME_SESSION_KEY, Local::now().timestamp() - 1)
                .unwrap();

            let resp = get(session, build_test_templater()).await;

            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[fixture]
        fn session() -> Session {
            let req = TestRequest::get().to_http_request();
            req.get_session()
        }
    }

    mod post {
        use crate::endpoints::authenticate::tests::build_test_templater;
        use crate::endpoints::authenticate::{
            post, Request, ERROR_CODE_SESSION_KEY, SESSION_KEY, TRIES_LEFT_SESSION_KEY,
        };
        use crate::endpoints::tests::{build_test_authenticator, query_parameter_of};
        use crate::endpoints::{
            authenticate, authorize, consent, generate_csrf_token, CSRF_SESSION_KEY,
            REDIRECT_QUERY_PARAM_ERROR, REDIRECT_QUERY_PARAM_ERROR_DESCRIPTION,
        };
        use actix_session::{Session, SessionExt};
        use actix_web::http::header::LOCATION;
        use actix_web::http::StatusCode;
        use actix_web::test::TestRequest;
        use actix_web::web::Form;
        use actix_web::HttpRequest;
        use rstest::{fixture, rstest};
        use test_log::test;
        use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
        use tiny_auth_business::oauth2;
        use tiny_auth_business::oidc::ResponseType;
        use tiny_auth_test_fixtures::authorize_endpoint::test_request;
        use tiny_auth_test_fixtures::store::user_store::{UNKNOWN_USER, USER};
        use url::Url;

        #[rstest]
        #[test(actix_web::test)]
        async fn missing_csrf_gives_error(session: Session) {
            let form = Form(Request {
                username: Some("user".to_owned()),
                password: Some("user".to_owned()),
                csrftoken: None,
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn emtpy_session_login_gives_error(session: Session) {
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
            let form = Form(Request {
                username: Some("user".to_owned()),
                password: Some("user".to_owned()),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn missing_username_gives_error(req: HttpRequest) {
            let session = req.get_session();
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: None,
                password: Some("user".to_owned()),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;
            let session = req.get_session();

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            assert_eq!(authenticate::ENDPOINT_NAME, url);
            assert_eq!(
                session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
                1
            );
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn missing_password_gives_error(req: HttpRequest) {
            let session = req.get_session();
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: Some("user".to_owned()),
                password: None,
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;
            let session = req.get_session();

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            assert_eq!(authenticate::ENDPOINT_NAME, url);
            assert_eq!(
                session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
                2
            );
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn unknown_user_gives_error(req: HttpRequest) {
            let session = req.get_session();
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: Some(UNKNOWN_USER.to_owned()),
                password: Some(UNKNOWN_USER.to_owned() + "wrong"),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;
            let session = req.get_session();

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            assert_eq!(authenticate::ENDPOINT_NAME, url);
            assert_eq!(
                session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
                3
            );
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn wrong_password_gives_error(req: HttpRequest) {
            let session = req.get_session();
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: Some(USER.to_owned()),
                password: Some(USER.to_owned() + "wrong"),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;
            let session = req.get_session();

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            assert_eq!(authenticate::ENDPOINT_NAME, url);
            assert_eq!(
                session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
                3
            );
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn correct_login_is_reported(req: HttpRequest) {
            let session = req.get_session();
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: Some(USER.to_owned()),
                password: Some(USER.to_owned()),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;
            let session = req.get_session();

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            assert_eq!(consent::ENDPOINT_NAME, url);
            assert_eq!(session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap(), None);
            assert_eq!(session.get::<String>(SESSION_KEY).unwrap().unwrap(), USER);
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn default_try_count_is_two(req: HttpRequest) {
            let session = req.get_session();
            session
                .insert(authorize::SESSION_KEY, test_request())
                .unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: Some(UNKNOWN_USER.to_owned()),
                password: Some(UNKNOWN_USER.to_owned()),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;
            let session = req.get_session();

            assert_eq!(resp.status(), StatusCode::SEE_OTHER);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            assert_eq!(authenticate::ENDPOINT_NAME, url);
            assert_eq!(
                session.get::<i32>(ERROR_CODE_SESSION_KEY).unwrap().unwrap(),
                3
            );
            assert_eq!(
                session.get::<i32>(TRIES_LEFT_SESSION_KEY).unwrap().unwrap(),
                2
            );
        }

        #[rstest]
        #[test(actix_web::test)]
        async fn no_tries_left_will_redirect_to_client(session: Session) {
            session
                .insert(
                    authorize::SESSION_KEY,
                    AuthorizeRequestState {
                        redirect_uri: Url::parse("http://redirect_uri.example").unwrap(),
                        response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                        ..test_request()
                    },
                )
                .unwrap();
            session.insert(TRIES_LEFT_SESSION_KEY, 1).unwrap();
            let csrftoken = generate_csrf_token();
            session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();

            let form = Form(Request {
                username: Some(UNKNOWN_USER.to_owned()),
                password: Some(UNKNOWN_USER.to_owned()),
                csrftoken: Some(csrftoken),
            });

            let resp = post(
                form,
                session,
                build_test_templater(),
                build_test_authenticator(),
            )
            .await;

            assert_eq!(resp.status(), StatusCode::FOUND);
            let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
            let url = Url::parse(url).unwrap();
            assert_eq!(
                Some(oauth2::ProtocolError::AccessDenied.to_string()),
                query_parameter_of(&url, REDIRECT_QUERY_PARAM_ERROR)
            );
            assert_eq!(
                Some("user failed to authenticate".to_owned()),
                query_parameter_of(&url, REDIRECT_QUERY_PARAM_ERROR_DESCRIPTION)
            );
        }

        #[fixture]
        fn req() -> HttpRequest {
            TestRequest::post().to_http_request()
        }

        #[fixture]
        fn session() -> Session {
            let req = TestRequest::post().to_http_request();
            req.get_session()
        }
    }
    fn build_test_templater() -> Data<dyn WebTemplater<AuthenticateContext>> {
        Data::from(Arc::new(TestTemplater) as Arc<dyn WebTemplater<_>>)
    }
}
