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

use super::{error_with_code, return_rendered_template, server_error};
use crate::endpoints::authenticate;
use crate::endpoints::authorize;
use crate::endpoints::parse_first_request;
use crate::endpoints::render_redirect_error;
use actix_session::Session;
use actix_web::http::StatusCode;
use actix_web::web;
use actix_web::HttpResponse;
use chrono::offset::Local;
use chrono::TimeZone;
use serde_derive::Deserialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
use tiny_auth_business::consent::Error;
use tiny_auth_business::consent::Handler;
use tiny_auth_business::consent::Request as BusinessRequest;
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc;
use tiny_auth_business::scope::ScopeDescription;
use tiny_auth_business::serde::deserialise_empty_as_none;
use tiny_auth_business::template::web::ErrorPage::ServerError;
use tiny_auth_business::template::web::{ConsentContext, ErrorPage, WebTemplater};
use tracing::{debug, instrument};
use tracing::{span, warn, Instrument, Level};
use url::Url;
use web::Data;

#[instrument(skip_all, name = "consent_get")]
pub async fn get(
    templater: Data<dyn WebTemplater<ConsentContext>>,
    session: Session,
    handler: Data<Handler>,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_consent_request(templater);
        }
        Some(v) => v,
    };
    let flow = span!(
        Level::DEBUG,
        "flow",
        state = first_request.state,
        nonce = first_request.nonce
    );
    async move {
        let username = match session.get::<String>(authenticate::SESSION_KEY) {
            Err(_) | Ok(None) => {
                debug!("unsolicited consent request, missing authentication session key");
                return render_invalid_consent_request(templater);
            }
            Ok(Some(v)) => v,
        };

        let can_skip_consent_screen = match handler
            .can_skip_consent_screen(&username, &first_request.client_id, &first_request.scopes)
            .await
        {
            Err(_) => {
                return render_invalid_consent_request(templater);
            }
            Ok(v) => v,
        };

        if can_skip_consent_screen {
            if first_request.prompts.contains(&oidc::Prompt::Consent) {
                debug!("user gave consent to all scopes but client requires explicit consent");
            } else {
                debug!("user gave consent to all scopes, skipping consent screen");
                return process_skipping_csrf(
                    first_request.scopes.iter().map(Clone::clone).collect(),
                    session,
                    templater,
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

        match build_context(&session, handler).await {
            Some(context) => {
                return_rendered_template(templater.instantiate(context), StatusCode::OK, || {
                    templater.instantiate_error_page(ServerError)
                })
            }
            None => server_error(templater.instantiate_error_page(ErrorPage::ServerError)),
        }
    }
    .instrument(flow)
    .await
}

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    csrftoken: Option<String>,

    #[serde(flatten)]
    scopes: BTreeMap<String, String>,
}

#[instrument(skip_all, name = "consent_post")]
pub async fn post(
    query: web::Form<Request>,
    session: Session,
    templater: Data<dyn WebTemplater<ConsentContext>>,
    handler: Data<Handler>,
) -> HttpResponse {
    if !super::is_csrf_valid(&query.csrftoken, &session) {
        debug!("CSRF protection violation detected");
        return render_invalid_consent_request(templater);
    }
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_consent_request(templater);
        }
        Some(v) => v,
    };
    let flow = span!(
        Level::DEBUG,
        "flow",
        state = first_request.state,
        nonce = first_request.nonce
    );
    process_skipping_csrf(
        query.0.scopes.into_keys().collect(),
        session,
        templater,
        handler,
        &first_request,
    )
    .instrument(flow)
    .await
}

async fn process_skipping_csrf(
    scopes: BTreeSet<String>,
    session: Session,
    templater: Data<dyn WebTemplater<ConsentContext>>,
    handler: Data<Handler>,
    first_request: &AuthorizeRequestState,
) -> HttpResponse {
    let username = match session.get::<String>(authenticate::SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(templater);
        }
        Ok(Some(username)) => username,
    };

    let auth_time = match session.get::<i64>(authenticate::AUTH_TIME_SESSION_KEY) {
        Err(_) | Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(templater);
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
            user_confirmed_scopes: &scopes,
            response_types: &first_request.response_types,
            auth_time,
            nonce: first_request.nonce.as_ref(),
            code_challenge: first_request.code_challenge.as_ref(),
        })
        .await
    {
        Ok(v) => v,
        Err(Error::ClientNotFound) | Err(Error::UserNotFound) | Err(Error::ScopesNotFound) => {
            return render_invalid_consent_request(templater);
        }
        Err(Error::TokenEncodingError) | Err(Error::AuthCodeNotGenerated) => {
            return server_error(templater.instantiate_error_page(ServerError))
        }
    };

    response
        .code
        .and_then(|v| response_parameters.insert("code", v));
    response
        .access_token
        .and_then(|v| response_parameters.insert("access_token", v.into()));
    response
        .id_token
        .and_then(|v| response_parameters.insert("id_token", v.into()));
    response
        .refresh_token
        .and_then(|v| response_parameters.insert("refresh_token", v.into()));
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

#[instrument(skip_all, name = "consent_cancel")]
pub async fn cancel(
    session: Session,
    templater: Data<dyn WebTemplater<ConsentContext>>,
) -> HttpResponse {
    let first_request = match parse_first_request(&session) {
        None => {
            return render_invalid_consent_request(templater);
        }
        Some(req) => req,
    };
    let _guard = span!(
        Level::DEBUG,
        "flow",
        state = first_request.state,
        nonce = first_request.nonce
    )
    .entered();
    debug!("cancelling flow");
    session.remove(authorize::SESSION_KEY);

    render_redirect_error(
        &first_request.redirect_uri,
        oidc::ProtocolError::OAuth2(oauth2::ProtocolError::AccessDenied),
        "user denied consent",
        &first_request.state,
        first_request.encode_redirect_to_fragment,
    )
}

fn render_invalid_consent_request(
    templater: Data<dyn WebTemplater<ConsentContext>>,
) -> HttpResponse {
    error_with_code(
        templater.instantiate_error_page(ErrorPage::InvalidConsentRequest),
        StatusCode::BAD_REQUEST,
    )
}

async fn build_context(session: &Session, handler: Data<Handler>) -> Option<ConsentContext> {
    let first_request = parse_first_request(session)?;
    let username = session.get::<String>(authenticate::SESSION_KEY).ok()??;
    let csrftoken = super::generate_csrf_token();
    let mut scopes: Vec<ScopeDescription> = Vec::new();
    for scope_name in &first_request.scopes {
        if let Some(scope) = handler.get_scope(scope_name).await {
            scopes.push(scope.into());
        }
    }

    if let Err(e) = session.insert(super::CSRF_SESSION_KEY, csrftoken.clone()) {
        warn!("Failed to construct context: {}", e);
        return None;
    }
    Some(ConsentContext {
        user: username,
        client: first_request.client_id,
        scopes,
        csrf_token: csrftoken,
    })
}

#[cfg(test)]
mod tests {
    use super::super::generate_csrf_token;
    use super::super::CSRF_SESSION_KEY;
    use super::*;
    use actix_session::SessionExt;
    use actix_web::http;
    use actix_web::test::TestRequest;
    use actix_web::web::Data;
    use actix_web::web::Form;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::sync::Arc;
    use test_log::test;
    use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
    use tiny_auth_business::consent::test_fixtures::handler;
    use tiny_auth_business::oidc::ResponseType;
    use tiny_auth_business::store::test_fixtures::PUBLIC_CLIENT;
    use tiny_auth_business::store::test_fixtures::USER;
    use tiny_auth_business::template::test_fixtures::TestTemplater;
    use url::Url;

    #[test(actix_web::test)]
    async fn empty_session_gives_error() {
        let req = TestRequest::get().to_http_request();
        let session = req.get_session();

        let resp = get(build_test_templater(), session, Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test(actix_web::test)]
    async fn missing_authentication_gives_error() {
        let req = TestRequest::get().to_http_request();
        let session = req.get_session();
        session
            .insert(authorize::SESSION_KEY, AuthorizeRequestState::default())
            .unwrap();

        let resp = get(build_test_templater(), session, Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test(actix_web::test)]
    async fn valid_request_is_rendered() {
        let req = TestRequest::get().to_http_request();
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

        let resp = get(build_test_templater(), session, Data::new(handler())).await;

        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[test(actix_web::test)]
    async fn wrong_csrf_gives_error() {
        let req = TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken + "wrong"),
            scopes: Default::default(),
        });

        let resp = post(
            request,
            session,
            build_test_templater(),
            Data::new(handler()),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test(actix_web::test)]
    async fn posting_empty_session_gives_error() {
        let req = TestRequest::post().to_http_request();
        let session = req.get_session();
        let csrftoken = generate_csrf_token();
        session.insert(CSRF_SESSION_KEY, &csrftoken).unwrap();
        let request = Form(Request {
            csrftoken: Some(csrftoken),
            scopes: Default::default(),
        });

        let resp = post(
            request,
            session,
            build_test_templater(),
            Data::new(handler()),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test(actix_web::test)]
    async fn posting_missing_authentication_gives_error() {
        let req = TestRequest::post().to_http_request();
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

        let resp = post(
            request,
            session,
            build_test_templater(),
            Data::new(handler()),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test(actix_web::test)]
    async fn successful_request_is_forwarded() {
        let req = TestRequest::post().to_http_request();
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

        let resp = post(
            request,
            session,
            build_test_templater(),
            Data::new(handler()),
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

    #[test(actix_web::test)]
    async fn successful_request_with_id_token_is_forwarded() {
        let req = TestRequest::post().to_http_request();
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

        let resp = post(
            request,
            session,
            build_test_templater(),
            Data::new(handler()),
        )
        .await;

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

    fn build_test_templater() -> Data<dyn WebTemplater<ConsentContext>> {
        Data::from(Arc::new(TestTemplater) as Arc<dyn WebTemplater<_>>)
    }
}
