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

use super::{error_with_code, return_rendered_template, server_error, REDIRECT_QUERY_PARAM_CODE};
use crate::endpoints::authenticate;
use crate::endpoints::authorize;
use crate::endpoints::parse_first_request;
use crate::endpoints::render_redirect_error;
use actix_session::Session;
use actix_web::http::header::LOCATION;
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
use tiny_auth_business::data::scope::ScopeDescription;
use tiny_auth_business::oauth2;
use tiny_auth_business::oidc;
use tiny_auth_business::serde::deserialise_empty_as_none;
use tiny_auth_business::template::web::ErrorPage::ServerError;
use tiny_auth_business::template::web::{ConsentContext, ErrorPage, WebTemplater};
use tracing::{debug, error, instrument};
use tracing::{span, warn, Instrument, Level};
use web::Data;

pub const ENDPOINT_NAME: &str = "consent";

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
            Err(e) => {
                debug!(%e, "unsolicited consent request, missing authentication session key");
                return render_invalid_consent_request(templater);
            }
            Ok(None) => {
                debug!("unsolicited consent request, missing authentication session key");
                return render_invalid_consent_request(templater);
            }
            Ok(Some(v)) => v,
        };

        let can_skip_consent_screen = match handler
            .can_skip_consent_screen(&username, &first_request.client_id, &first_request.scopes)
            .await
        {
            Err(e) => {
                debug!(%e, "unsolicited consent request, missing authentication session key");
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
        Err(e) => {
            debug!(%e, "unsolicited consent request");
            return render_invalid_consent_request(templater);
        }
        Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(templater);
        }
        Ok(Some(username)) => username,
    };

    let auth_time = match session.get::<i64>(authenticate::AUTH_TIME_SESSION_KEY) {
        Err(e) => {
            debug!(%e, "unsolicited consent request");
            return render_invalid_consent_request(templater);
        }
        Ok(None) => {
            debug!("unsolicited consent request");
            return render_invalid_consent_request(templater);
        }
        Ok(Some(username)) => username,
    };
    let auth_time = Local
        .timestamp_opt(auth_time, 0)
        .single()
        .unwrap_or(Local::now());

    let mut redirect_uri = first_request.redirect_uri.clone();
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
        .and_then(|v| response_parameters.insert(REDIRECT_QUERY_PARAM_CODE, v));
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
        .and_then(|_| response_parameters.insert("token_type", "bearer".to_owned()));
    first_request
        .state
        .as_ref()
        .and_then(|v| response_parameters.insert("state", v.to_owned()));

    if first_request.encode_redirect_to_fragment {
        let fragment = serde_urlencoded::to_string(response_parameters).unwrap_or_else(|e| {
            error!(%e, "failed to serialize response parameters");
            String::new()
        });
        redirect_uri.set_fragment(Some(&fragment));
    } else {
        redirect_uri
            .query_pairs_mut()
            .extend_pairs(response_parameters);
    }

    session.remove(authorize::SESSION_KEY);

    HttpResponse::Found()
        .insert_header((LOCATION, redirect_uri.as_str()))
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
    use crate::endpoints::tests::query_parameter_of;
    use crate::endpoints::{REDIRECT_QUERY_PARAM_CODE, REDIRECT_QUERY_PARAM_STATE};
    use actix_session::SessionExt;
    use actix_web::http::header::LOCATION;
    use actix_web::test::TestRequest;
    use actix_web::web::Data;
    use actix_web::web::Form;
    use pretty_assertions::assert_eq;
    use rstest::{fixture, rstest};
    use std::collections::HashMap;
    use std::sync::Arc;
    use test_log::test;
    use tiny_auth_business::authorize_endpoint::AuthorizeRequestState;
    use tiny_auth_business::oidc::ResponseType;
    use tiny_auth_test_fixtures::authorize_endpoint::test_request;
    use tiny_auth_test_fixtures::consent::handler;
    use tiny_auth_test_fixtures::data::client::PUBLIC_CLIENT;
    use tiny_auth_test_fixtures::store::user_store::USER;
    use tiny_auth_test_fixtures::template::TestTemplater;
    use url::Url;

    #[rstest]
    #[test(actix_web::test)]
    async fn empty_session_gives_error(session: Session) {
        let resp = get(build_test_templater(), session, Data::new(handler())).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn missing_authentication_gives_error(session: Session) {
        session
            .insert(authorize::SESSION_KEY, test_request())
            .unwrap();

        let resp = get(build_test_templater(), session, Data::new(handler())).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn valid_request_is_rendered(session: Session) {
        let redirect_uri = PUBLIC_CLIENT.redirect_uris[0].clone();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
            redirect_uri: Some(redirect_uri),
            state: Some("state".to_owned()),
            response_type: Some("code".to_owned()),
            scope: Some("openid".to_owned()),
            ..authorize::Request::default()
        };
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    client_id: PUBLIC_CLIENT.client_id.to_owned(),
                    redirect_uri: first_request.redirect_uri.unwrap().clone(),
                    state: first_request.state.clone(),
                    response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                    scopes: vec!["openid".to_owned()],
                    ..test_request()
                },
            )
            .unwrap();

        session.insert(authenticate::SESSION_KEY, USER).unwrap();

        let resp = get(build_test_templater(), session, Data::new(handler())).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn wrong_csrf_gives_error(session: Session) {
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

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn posting_empty_session_gives_error(session: Session) {
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

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn posting_missing_authentication_gives_error(session: Session) {
        session
            .insert(authorize::SESSION_KEY, test_request())
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

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn successful_request_is_forwarded(session: Session) {
        let redirect_uri = PUBLIC_CLIENT.redirect_uris[0].clone();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
            redirect_uri: Some(redirect_uri.clone()),
            state: Some("state".to_owned()),
            response_type: Some("code".to_owned()),
            scope: Some("".to_owned()),
            ..authorize::Request::default()
        };
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    client_id: PUBLIC_CLIENT.client_id.to_owned(),
                    redirect_uri: first_request.redirect_uri.clone().unwrap(),
                    state: first_request.state.clone(),
                    response_types: vec![ResponseType::OAuth2(oauth2::ResponseType::Code)],
                    scopes: vec!["openid".to_owned()],
                    ..test_request()
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

        assert_eq!(resp.status(), StatusCode::FOUND);

        let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();

        assert_eq!(redirect_uri.scheme(), url.scheme());
        assert_eq!(redirect_uri.domain(), url.domain());
        assert_eq!(redirect_uri.port(), url.port());
        assert_eq!(redirect_uri.path(), url.path());
        assert_eq!(
            first_request.state.to_owned(),
            query_parameter_of(&url, REDIRECT_QUERY_PARAM_STATE)
        );
        assert!(!query_parameter_of(&url, REDIRECT_QUERY_PARAM_CODE)
            .unwrap()
            .is_empty());
    }

    #[rstest]
    #[test(actix_web::test)]
    async fn successful_request_with_id_token_is_forwarded(session: Session) {
        let redirect_uri = PUBLIC_CLIENT.redirect_uris[0].clone();
        let first_request = authorize::Request {
            client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
            redirect_uri: Some(redirect_uri.clone()),
            state: Some("state".to_owned()),
            response_type: Some("id_token code".to_owned()),
            scope: Some("".to_owned()),
            ..authorize::Request::default()
        };
        session
            .insert(
                authorize::SESSION_KEY,
                AuthorizeRequestState {
                    client_id: PUBLIC_CLIENT.client_id.to_owned(),
                    redirect_uri: first_request.redirect_uri.clone().unwrap(),
                    state: first_request.state.clone(),
                    response_types: vec![
                        ResponseType::OAuth2(oauth2::ResponseType::Code),
                        ResponseType::Oidc(oidc::OidcResponseType::IdToken),
                    ],
                    scopes: vec!["openid".to_owned()],
                    encode_redirect_to_fragment: true,
                    ..test_request()
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

        assert_eq!(resp.status(), StatusCode::FOUND);

        let url = resp.headers().get(LOCATION).unwrap().to_str().unwrap();
        let url = Url::parse(url).unwrap();

        assert_eq!(redirect_uri.scheme(), url.scheme());
        assert_eq!(redirect_uri.domain(), url.domain());
        assert_eq!(redirect_uri.port(), url.port());
        assert_eq!(redirect_uri.path(), url.path());

        let fragment = url.fragment().unwrap_or("");
        let response_parameters =
            serde_urlencoded::from_str::<HashMap<String, String>>(fragment).unwrap();

        assert_eq!(
            Some(&REDIRECT_QUERY_PARAM_STATE.to_owned()),
            response_parameters.get(REDIRECT_QUERY_PARAM_STATE)
        );
        assert!(!response_parameters
            .get(REDIRECT_QUERY_PARAM_CODE)
            .unwrap()
            .is_empty());
        assert!(!response_parameters.get("id_token").unwrap().is_empty());
    }

    #[fixture]
    fn session() -> Session {
        let req = TestRequest::post().to_http_request();
        req.get_session()
    }

    fn build_test_templater() -> Data<dyn WebTemplater<ConsentContext>> {
        Data::from(Arc::new(TestTemplater) as Arc<dyn WebTemplater<_>>)
    }
}
