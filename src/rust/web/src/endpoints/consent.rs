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
use crate::endpoints::authenticate;
use crate::endpoints::authorize;
use crate::endpoints::parse_first_request;
use crate::endpoints::render_redirect_error;
use crate::endpoints::render_template_with_context;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use chrono::offset::Local;
use chrono::TimeZone;
use log::debug;
use log::warn;
use serde_derive::Deserialize;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use tera::Context;
use tera::Tera;
use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
use tiny_auth_business::consent::Error;
use tiny_auth_business::consent::Handler;
use tiny_auth_business::consent::Request as BusinessRequest;
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc;
use tiny_auth_business::scope::ScopeDescription;
use tiny_auth_business::serde::deserialise_empty_as_none;
use tiny_auth_business::store::ScopeStore;
use url::Url;

pub async fn get(
    tera: web::Data<Tera>,
    session: Session,
    handler: web::Data<Handler>,
    scope_store: web::Data<Arc<dyn ScopeStore>>,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_consent_request(&tera);
        }
        Some(v) => v,
    };

    let username = match session.get::<String>(authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request, missing authentication session key");
            return render_invalid_consent_request(&tera);
        }
        Ok(Some(v)) => v,
    };

    let can_skip_consent_screen = match handler.can_skip_consent_screen(
        &username,
        &first_request.client_id,
        &first_request.scopes,
    ) {
        Err(_) => {
            return render_invalid_consent_request(&tera);
        }
        Ok(v) => v,
    };

    if can_skip_consent_screen {
        if first_request.prompts.contains(&oidc::Prompt::Consent) {
            debug!(
                "user '{}' gave consent to all scopes but client requires explicit consent",
                username
            );
        } else {
            debug!(
                "user '{}' gave consent to all scopes, skipping consent screen",
                username
            );
            return process_skipping_csrf(
                web::Form(Request {
                    csrftoken: None,
                    scopes: first_request
                        .scopes
                        .iter()
                        .map(|v| (v.clone(), String::new()))
                        .collect(),
                }),
                session,
                tera,
                handler,
                &first_request,
            )
            .await;
        }
    } else if first_request.prompts.contains(&oidc::Prompt::None) {
        return render_redirect_error(
            &first_request.redirect_uri,
            oidc::ProtocolError::Oidc(oidc::OidcProtocolError::ConsentRequired),
            "User didn't give consent to all scopes",
            &first_request.state,
            first_request.encode_redirect_to_fragment,
        );
    }

    match build_context(&session, scope_store) {
        Some(context) => {
            render_template_with_context("consent.html.j2", StatusCode::OK, &tera, &context)
        }
        None => server_error(&tera),
    }
}

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    csrftoken: Option<String>,

    #[serde(flatten)]
    scopes: BTreeMap<String, String>,
}

pub async fn post(
    query: web::Form<Request>,
    session: Session,
    tera: web::Data<Tera>,
    handler: web::Data<Handler>,
) -> HttpResponse {
    if !super::is_csrf_valid(&query.csrftoken, &session) {
        debug!("CSRF protection violation detected");
        return render_invalid_consent_request(&tera);
    }
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_consent_request(&tera);
        }
        Some(v) => v,
    };
    process_skipping_csrf(query, session, tera, handler, &first_request).await
}

async fn process_skipping_csrf(
    query: web::Form<Request>,
    session: Session,
    tera: web::Data<Tera>,
    handler: web::Data<Handler>,
    first_request: &AuthorizeRequestState,
) -> HttpResponse {
    let username = match session.get::<String>(authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(&tera);
        }
        Ok(Some(username)) => username,
    };

    let auth_time = match session.get::<i64>(authenticate::AUTH_TIME_SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(&tera);
        }
        Ok(Some(username)) => username,
    };
    let auth_time = Local
        .timestamp_opt(auth_time, 0)
        .single()
        .unwrap_or(Local::now());

    let mut url = Url::parse(&first_request.redirect_uri)
        .expect("should have been validated upon registration");
    let mut response_parameters = HashMap::new();

    let response = match handler
        .issue_token(BusinessRequest {
            client_id: &first_request.client_id,
            redirect_uri: &first_request.redirect_uri,
            authenticated_username: &username,
            requested_scopes: &first_request.scopes,
            user_confirmed_scopes: &query.scopes.keys().map(Clone::clone).collect(),
            response_types: &first_request.response_types,
            auth_time,
            nonce: first_request.nonce.as_ref(),
            code_challenge: first_request.code_challenge.as_ref(),
        })
        .await
    {
        Ok(v) => v,
        Err(Error::ClientNotFound) | Err(Error::UserNotFound) => {
            return render_invalid_consent_request(&tera);
        }
        Err(Error::TokenEncodingError) => return server_error(&tera),
    };

    response
        .code
        .and_then(|v| response_parameters.insert("code", v));
    response
        .access_token
        .and_then(|v| response_parameters.insert("access_token", v));
    response
        .id_token
        .and_then(|v| response_parameters.insert("id_token", v));
    response
        .refresh_token
        .and_then(|v| response_parameters.insert("refresh_token", v));
    response
        .expiration
        .and_then(|v| response_parameters.insert("expires_in", v.num_seconds().to_string()));
    response
        .expiration
        .and_then(|_| response_parameters.insert("token_type", "bearer".to_string()));
    first_request
        .state
        .as_ref()
        .and_then(|v| response_parameters.insert("state", v.to_string()));

    if first_request.encode_redirect_to_fragment {
        let fragment =
            serde_urlencoded::to_string(response_parameters).expect("failed to serialize");
        url.set_fragment(Some(&fragment));
    } else {
        url.query_pairs_mut().extend_pairs(response_parameters);
    }

    session.remove(authorize::SESSION_KEY);

    HttpResponse::Found()
        .insert_header(("Location", url.as_str()))
        .finish()
}

pub async fn cancel(session: Session, tera: web::Data<Tera>) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_consent_request(&tera);
        }
        Some(req) => req,
    };

    session.remove(authorize::SESSION_KEY);

    render_redirect_error(
        &first_request.redirect_uri,
        oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
        "user denied consent",
        &first_request.state,
        first_request.encode_redirect_to_fragment,
    )
}

fn render_invalid_consent_request(tera: &Tera) -> HttpResponse {
    render_template(
        "invalid_consent_request.html.j2",
        StatusCode::BAD_REQUEST,
        tera,
    )
}

fn build_context(
    session: &Session,
    scope_store: web::Data<Arc<dyn ScopeStore>>,
) -> Option<Context> {
    let mut context = Context::new();

    let first_request = parse_first_request(session)?;
    context.insert(super::CLIENT_ID_CONTEXT, &first_request.client_id);

    let mut scopes: Vec<ScopeDescription> = Vec::new();
    for scope_name in &first_request.scopes {
        if let Some(scope) = scope_store.get(scope_name) {
            scopes.push(scope.into());
        }
    }
    context.insert(super::SCOPES_CONTEXT, &scopes);

    let username = session.get::<String>(authenticate::SESSION_KEY).ok()??;
    context.insert(super::USER_NAME_CONTEXT, &username);

    let csrftoken = super::generate_csrf_token();
    context.insert(super::CSRF_CONTEXT, &csrftoken);

    if let Err(e) = session.insert(super::CSRF_SESSION_KEY, csrftoken) {
        warn!("Failed to construct context: {}", e);
        return None;
    }
    Some(context)
}

#[cfg(test)]
mod tests {
    use super::super::generate_csrf_token;
    use super::super::CSRF_SESSION_KEY;
    use super::*;
    use crate::endpoints::tests::build_test_tera;
    use actix_session::SessionExt;
    use actix_web::http;
    use actix_web::test;
    use actix_web::web::Data;
    use actix_web::web::Form;
    use std::collections::HashMap;
    use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
    use tiny_auth_business::consent::test_fixtures::handler;
    use tiny_auth_business::oidc::ResponseType;
    use tiny_auth_business::store::test_fixtures::build_test_scope_store;
    use tiny_auth_business::store::test_fixtures::PUBLIC_CLIENT;
    use tiny_auth_business::store::test_fixtures::USER;
    use url::Url;

    #[test_log::test(actix_web::test)]
    async fn empty_session_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();

        let resp = get(
            build_test_tera(),
            session,
            Data::new(handler()),
            Data::new(build_test_scope_store()),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn missing_authentication_gives_error() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();

        let resp = get(
            build_test_tera(),
            session,
            Data::new(handler()),
            Data::new(build_test_scope_store()),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn valid_request_is_rendered() {
        let req = test::TestRequest::get().to_http_request();
        let session = req.get_session();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some("http://localhost/".to_string()),
            state: Some("state".to_string()),
            response_type: Some("code".to_string()),
            scope: Some("openid".to_string()),
            ..authorize::Request::default()
        };
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    client_id: PUBLIC_CLIENT.to_string(),
                    redirect_uri: first_request.redirect_uri.unwrap().clone(),
                    state: first_request.state.clone(),
                    response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                    scopes: vec!["openid".to_string()],
                    ..AuthorizeRequestState::default()
                },
            )
            .unwrap();

        session.insert(authenticate::SESSION_KEY, USER).unwrap();

        let resp = get(
            build_test_tera(),
            session,
            Data::new(handler()),
            Data::new(build_test_scope_store()),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[test_log::test(actix_web::test)]
    async fn wrong_csrf_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken + "wrong"),
            scopes: Default::default(),
        });

        let resp = post(request, session, build_test_tera(), Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn posting_empty_session_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
            scopes: Default::default(),
        });

        let resp = post(request, session, build_test_tera(), Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn posting_missing_authentication_gives_error() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();
        session
            .insert(authenticate::AUTH_TIME_SESSION_KEY, 0)
            .unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
            scopes: Default::default(),
        });

        let resp = post(request, session, build_test_tera(), Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(actix_web::test)]
    async fn successful_request_is_forwarded() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some("http://localhost/".to_string()),
            state: Some("state".to_string()),
            response_type: Some("code".to_string()),
            scope: Some("".to_string()),
            ..authorize::Request::default()
        };
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    client_id: PUBLIC_CLIENT.to_string(),
                    redirect_uri: first_request.redirect_uri.clone().unwrap(),
                    state: first_request.state.clone(),
                    response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                    scopes: vec!["openid".to_string()],
                    ..AuthorizeRequestState::default()
                },
            )
            .unwrap();
        session
            .insert(authenticate::AUTH_TIME_SESSION_KEY, 0)
            .unwrap();
        session.insert(authenticate::SESSION_KEY, USER).unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
            scopes: Default::default(),
        });

        let resp = post(request, session, build_test_tera(), Data::new(handler())).await;

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

    #[test_log::test(actix_web::test)]
    async fn successful_request_with_id_token_is_forwarded() {
        let req = test::TestRequest::post().to_http_request();
        let session = req.get_session();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some("http://localhost/".to_string()),
            state: Some("state".to_string()),
            response_type: Some("id_token code".to_string()),
            scope: Some("".to_string()),
            ..authorize::Request::default()
        };
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    client_id: PUBLIC_CLIENT.to_string(),
                    redirect_uri: first_request.redirect_uri.clone().unwrap(),
                    state: first_request.state.clone(),
                    response_types: vec![
                        ResponseType::OAuth2(oauth2::ResponseType::Code),
                        ResponseType::Oidc(oidc::OidcResponseType::IdToken),
                    ],
                    scopes: vec!["openid".to_string()],
                    encode_redirect_to_fragment: true,
                    ..AuthorizeRequestState::default()
                },
            )
            .unwrap();
        session
            .insert(authenticate::AUTH_TIME_SESSION_KEY, 0)
            .unwrap();
        session.insert(authenticate::SESSION_KEY, USER).unwrap();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
            scopes: Default::default(),
        });

        let resp = post(request, session, build_test_tera(), Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::FOUND);

        let url = resp.headers().get("Location").unwrap().to_str().unwrap();
        let url = dbg!(Url::parse(url).unwrap());
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
