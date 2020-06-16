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
use crate::business::token::TokenCreator;
use crate::domain::token::Token;
use crate::http::endpoints::authenticate;
use crate::http::endpoints::authorize;
use crate::http::endpoints::render_template_with_context;
use crate::protocol::oauth2;
use crate::protocol::oidc;
use crate::store::AuthorizationCodeStore;
use crate::store::ClientStore;
use crate::store::UserStore;

use std::collections::HashMap;

use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;

use actix_session::Session;

use url::Url;

use tera::Context;
use tera::Tera;

use chrono::offset::Local;
use chrono::Duration;

use log::debug;
use log::error;
use log::warn;

use serde_derive::Deserialize;

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    csrftoken: Option<String>,
}

pub async fn get(tera: web::Data<Tera>, session: Session) -> HttpResponse {
    match session.get::<String>(authorize::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(&tera);
        }
        _ => {}
    }

    match session.get::<String>(authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(&tera);
        }
        _ => {}
    }

    match build_context(&session) {
        Some(context) => {
            render_template_with_context("consent.html.j2", StatusCode::OK, &tera, &context)
        }
        None => server_error(&tera),
    }
}

pub async fn post(
    query: web::Form<Request>,
    session: Session,
    tera: web::Data<Tera>,
    client_store: web::Data<Box<dyn ClientStore>>,
    user_store: web::Data<Box<dyn UserStore>>,
    auth_code_store: web::Data<Box<dyn AuthorizationCodeStore>>,
    token_creator: web::Data<TokenCreator>,
) -> HttpResponse {
    if !super::is_csrf_valid(&query.csrftoken, &session) {
        debug!("CSRF protection violation detected");
        return render_invalid_consent_request(&tera);
    }

    let first_request = match session.get::<String>(authorize::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(&tera);
        }
        Ok(Some(req)) => req,
    };

    let username = match session.get::<String>(authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(&tera);
        }
        Ok(Some(username)) => username,
    };

    let first_request = match serde_urlencoded::from_str::<authorize::Request>(&first_request) {
        Err(e) => {
            error!("Failed to deserialize initial request. {}", e);
            return server_error(&tera);
        }
        Ok(req) => req,
    };

    let client_name = first_request.client_id.as_ref().unwrap();
    let response_type = first_request
        .response_type
        .as_deref()
        .map(authorize::parse_response_type)
        .flatten()
        .unwrap();
    let redirect_uri = first_request.redirect_uri.unwrap();
    let mut url = Url::parse(&redirect_uri).expect("should have been validated upon registration");
    let mut response_parameters = HashMap::new();
    let mut encode_to_fragment = false;

    if response_type.contains(&oidc::ResponseType::OAuth2(oauth2::ResponseType::Code)) {
        let code = auth_code_store.get_authorization_code(
            client_name,
            &username,
            &redirect_uri,
            Local::now(),
        );
        response_parameters.insert("code", code);
    }

    if response_type.contains(&oidc::ResponseType::Oidc(oidc::OidcResponseType::IdToken)) {
        encode_to_fragment = true;
        let user = match user_store.get(&username) {
            None => {
                debug!("user {} not found", username);
                return render_invalid_consent_request(&tera);
            }
            Some(user) => user,
        };

        let client = match client_store.get(client_name) {
            None => {
                debug!("client {} not found", client_name);
                return render_invalid_consent_request(&tera);
            }
            Some(client) => client,
        };

        let token = Token::build(&user, &client, Local::now() + Duration::minutes(1));

        let encoded_token = match token_creator.create(token) {
            Err(e) => {
                debug!("failed to encode token: {}", e);
                return server_error(&tera);
            }
            Ok(token) => token,
        };
        response_parameters.insert("id_token", encoded_token);
    }

    if response_type.contains(&oidc::ResponseType::OAuth2(oauth2::ResponseType::Token)) {
        encode_to_fragment = true;
        // TODO Issue #7
    }

    first_request
        .state
        .and_then(|v| response_parameters.insert("state", v));

    if encode_to_fragment {
        let fragment =
            serde_urlencoded::to_string(response_parameters).expect("failed to serialize");
        url.set_fragment(Some(&fragment));
    } else {
        url.query_pairs_mut().extend_pairs(response_parameters);
    }

    HttpResponse::Found()
        .set_header("Location", url.as_str())
        .finish()
}

fn render_invalid_consent_request(tera: &tera::Tera) -> HttpResponse {
    render_template(
        "invalid_consent_request.html.j2",
        StatusCode::BAD_REQUEST,
        tera,
    )
}

fn build_context(session: &Session) -> Option<Context> {
    let mut context = Context::new();

    let csrftoken = super::generate_csrf_token();
    context.insert(super::CSRF_CONTEXT, &csrftoken);

    if let Err(e) = session.set(super::CSRF_SESSION_KEY, csrftoken) {
        warn!("Failed to construct context: {}", e);
        return None;
    }
    Some(context)
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
    use crate::http::state::tests::build_test_auth_code_store;
    use crate::http::state::tests::build_test_client_store;
    use crate::http::state::tests::build_test_tera;
    use crate::http::state::tests::build_test_token_creator;
    use crate::http::state::tests::build_test_user_store;
    use crate::store::tests::PUBLIC_CLIENT;
    use crate::store::tests::USER;

    #[actix_rt::test]
    async fn empty_session_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();

        let resp = get(build_test_tera(), session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn missing_authentication_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session.set(authorize::SESSION_KEY, "dummy").unwrap();

        let resp = get(build_test_tera(), session).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn valid_request_is_rendered() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session.set(authorize::SESSION_KEY, "dummy").unwrap();
        session.set(authenticate::SESSION_KEY, "user").unwrap();

        let resp = get(build_test_tera(), session).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn wrong_csrf_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken + "wrong"),
        });

        let resp = post(
            request,
            session,
            build_test_tera(),
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn posting_empty_session_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
        });

        let resp = post(
            request,
            session,
            build_test_tera(),
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn posting_missing_authentication_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session.set(authorize::SESSION_KEY, "dummy").unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
        });

        let resp = post(
            request,
            session,
            build_test_tera(),
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn successful_request_is_forwarded() {
        let req = test::TestRequest::post().to_http_request();
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
            response_type: Some("code".to_string()),
            scope: None,
            ui_locales: None,
        };
        session
            .set(
                authorize::SESSION_KEY,
                &serde_urlencoded::to_string(first_request.clone()).unwrap(),
            )
            .unwrap();
        session.set(authenticate::SESSION_KEY, USER).unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
        });

        let resp = post(
            request,
            session,
            build_test_tera(),
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

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

    #[actix_rt::test]
    async fn successful_request_with_id_token_is_forwarded() {
        let req = test::TestRequest::post().to_http_request();
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
            response_type: Some("id_token code".to_string()),
            scope: None,
            ui_locales: None,
        };
        session
            .set(
                authorize::SESSION_KEY,
                &serde_urlencoded::to_string(first_request.clone()).unwrap(),
            )
            .unwrap();
        session.set(authenticate::SESSION_KEY, USER).unwrap();
        let csrftoken = generate_csrf_token();
        session.set(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
        });

        let resp = post(
            request,
            session,
            build_test_tera(),
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::FOUND);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();
        let expected_url = Url::parse(first_request.redirect_uri.as_ref().unwrap()).unwrap();

        assert_eq!(expected_url.scheme(), url.scheme());
        assert_eq!(expected_url.domain(), url.domain());
        assert_eq!(expected_url.port(), url.port());
        assert_eq!(expected_url.path(), url.path());

        let fragment = url.fragment().unwrap_or("");
        let response_parameters =
            serde_urlencoded::from_str::<HashMap<String, String>>(fragment).unwrap();

        assert_eq!(Some(&"state".to_string()), response_parameters.get("state"));
        assert!(!response_parameters.get("code").unwrap().is_empty());
        assert!(!response_parameters.get("id_token").unwrap().is_empty());
    }
}
