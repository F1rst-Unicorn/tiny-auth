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
use crate::business::token::TokenCreator;
use crate::domain::client::Client;
use crate::domain::token::Token;
use crate::http::endpoints::render_json_error;
use crate::protocol::oauth2;
use crate::protocol::oauth2::ClientType;
use crate::protocol::oauth2::GrantType;
use crate::protocol::oidc::ProtocolError;
use crate::store::AuthorizationCodeStore;
use crate::store::ClientStore;
use crate::store::UserStore;

use actix_web::http::HeaderValue;
use actix_web::web;
use actix_web::HttpRequest;
use actix_web::HttpResponse;

use serde_derive::Deserialize;
use serde_derive::Serialize;

use chrono::offset::Local;
use chrono::Duration;

use log::debug;

// Recommended lifetime is 10 minutes
// https://tools.ietf.org/html/rfc6749#section-4.1.2
pub const AUTH_CODE_LIFE_TIME: i64 = 10;

#[derive(Deserialize)]
pub struct Request {
    grant_type: Option<GrantType>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    code: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    redirect_uri: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    client_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    access_token: String,

    token_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

pub async fn post(
    headers: HttpRequest,
    request: web::Form<Request>,
    client_store: web::Data<Box<dyn ClientStore>>,
    user_store: web::Data<Box<dyn UserStore>>,
    auth_code_store: web::Data<Box<dyn AuthorizationCodeStore>>,
    token_creator: web::Data<TokenCreator>,
) -> HttpResponse {
    if request.grant_type.is_none() {
        return render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing parameter grant_type",
        );
    }

    if request.code.is_none() {
        return render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing parameter code",
        );
    }

    if request.redirect_uri.is_none() {
        return render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing parameter redirect_uri",
        );
    }

    if request.client_id.is_none() {
        return render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing parameter client_id",
        );
    }

    match request.grant_type.as_ref().unwrap() {
        GrantType::AuthorizationCode => grant_with_authorization_code(
            headers,
            request,
            client_store,
            user_store,
            auth_code_store,
            token_creator,
        ),
        _ => render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::UnsupportedGrantType),
            "grant_type must be authorization_code",
        ),
    }
}

pub fn grant_with_authorization_code(
    headers: HttpRequest,
    request: web::Form<Request>,
    client_store: web::Data<Box<dyn ClientStore>>,
    user_store: web::Data<Box<dyn UserStore>>,
    auth_code_store: web::Data<Box<dyn AuthorizationCodeStore>>,
    token_creator: web::Data<TokenCreator>,
) -> HttpResponse {
    let client_id = request.client_id.as_ref().unwrap();
    let client = match client_store.get(client_id) {
        None => {
            debug!("client '{}' not found", client_id);
            return render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "client id or password wrong",
            );
        }
        Some(client) => client,
    };

    if let ClientType::Confidential { .. } = client.client_type {
        if let Some(response) = authenticate_client(headers, &client) {
            return response;
        }
    }

    let code = request.code.as_ref().unwrap();
    let record = match auth_code_store.validate(client_id, &code, Local::now()) {
        None => {
            debug!(
                "No authorization code found for client '{}' with code '{}'",
                client_id, code
            );
            return render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                "Invalid code",
            );
        }
        Some(record) => record,
    };

    if &record.redirect_uri != request.redirect_uri.as_ref().unwrap() {
        debug!("redirect_uri is wrong");
        return render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
            "Invalid code",
        );
    }

    if record.stored_duration > Duration::minutes(AUTH_CODE_LIFE_TIME) {
        debug!("code has expired");
        return render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
            "Invalid code",
        );
    }

    let user = match user_store.get(&record.username) {
        None => {
            debug!("user {} not found", record.username);
            return render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                "User not found",
            );
        }
        Some(user) => user,
    };

    let token = Token::build(&user, &client, Local::now() + Duration::minutes(1));

    let encoded_token = match token_creator.create(token) {
        Err(e) => {
            debug!("failed to encode token: {}", e);
            return render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::ServerError),
                "token encoding failed",
            );
        }
        Ok(token) => token,
    };

    HttpResponse::Ok().json(Response {
        access_token: encoded_token.clone(),
        token_type: "bearer".to_string(),
        expires_in: Some(60),
        refresh_token: None,
        scope: None,
        id_token: Some(encoded_token),
    })
}

fn authenticate_client(headers: HttpRequest, client: &Client) -> Option<HttpResponse> {
    let (client_name, password) = match headers.headers().get("Authorization") {
        Some(value) => match parse_authorization(value) {
            Some(x) => x,
            None => {
                return Some(render_json_error(
                    ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                    "Invalid authorization header",
                ));
            }
        },
        None => {
            return Some(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                "Missing authorization header",
            ));
        }
    };

    if *client.client_id != client_name {
        return Some(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
            "Invalid authorization header",
        ));
    }

    if !client.is_password_correct(&password) {
        Some(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
            "client id or password wrong",
        ))
    } else {
        None
    }
}

fn parse_authorization(value: &HeaderValue) -> Option<(String, String)> {
    let value = match value.to_str() {
        Err(e) => {
            debug!("decoding of authorization header failed. {}", e);
            return None;
        }
        Ok(value) => value,
    };

    if !value.starts_with("Basic ") {
        debug!("Malformed HTTP basic authorization header '{}'", value);
        return None;
    }
    let value = value.replacen("Basic ", "", 1);

    let credentials = match base64::decode(value) {
        Err(e) => {
            debug!("base64 decoding of authorization header failed. {}", e);
            return None;
        }
        Ok(cred) => cred,
    };

    let credentials = match String::from_utf8(credentials) {
        Err(e) => {
            debug!("utf-8 decoding of authorization header failed. {}", e);
            return None;
        }
        Ok(cred) => cred,
    };

    let split: Vec<String> = credentials.splitn(2, ':').map(str::to_string).collect();
    if split.len() == 2 {
        Some((split[0].clone(), split[1].clone()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http;
    use actix_web::test;
    use actix_web::web::Form;

    use chrono::offset::Local;

    use crate::http::endpoints::tests::read_response;
    use crate::http::endpoints::ErrorResponse;
    use crate::http::state::tests::build_test_auth_code_store;
    use crate::http::state::tests::build_test_client_store;
    use crate::http::state::tests::build_test_token_creator;
    use crate::http::state::tests::build_test_user_store;
    use crate::protocol::oauth2::ProtocolError;
    use crate::protocol::oidc::ProtocolError as OidcError;
    use crate::store::tests::CONFIDENTIAL_CLIENT;
    use crate::store::tests::PUBLIC_CLIENT;
    use crate::store::tests::UNKNOWN_CLIENT_ID;
    use crate::store::tests::USER;

    #[actix_rt::test]
    async fn missing_grant_type_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: None,
            code: Some("fdsa".to_string()),
            client_id: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[actix_rt::test]
    async fn missing_code_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: None,
            client_id: Some("fdsa".to_string()),
            redirect_uri: Some("fdsa".to_string()),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[actix_rt::test]
    async fn missing_client_id_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: None,
            redirect_uri: Some("fdsa".to_string()),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[actix_rt::test]
    async fn missing_redirect_uri_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: Some("fdsa".to_string()),
            redirect_uri: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[actix_rt::test]
    async fn unknown_client_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: Some(UNKNOWN_CLIENT_ID.to_string()),
            redirect_uri: Some("fdsa".to_string()),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidRequest),
            response.error
        );
    }

    #[actix_rt::test]
    async fn unknown_auth_code_is_rejected() {
        // Don't register any auth_code
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some("fdsa".to_string()),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some("fdsa".to_string()),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(OidcError::from(ProtocolError::InvalidGrant), response.error);
    }

    #[actix_rt::test]
    async fn wrong_redirect_uri_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            PUBLIC_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri + "/wrong"),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(OidcError::from(ProtocolError::InvalidGrant), response.error);
    }

    #[actix_rt::test]
    async fn expired_code_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let creation_time = Local::now() - Duration::minutes(2 * AUTH_CODE_LIFE_TIME);
        let auth_code = auth_code_store.get_authorization_code(
            PUBLIC_CLIENT,
            USER,
            &redirect_uri,
            creation_time,
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(OidcError::from(ProtocolError::InvalidGrant), response.error);
    }

    #[actix_rt::test]
    async fn valid_token_is_issued() {
        let req = test::TestRequest::post().to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            PUBLIC_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert_eq!(None, response.refresh_token);
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn confidential_client_without_basic_auth_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[actix_rt::test]
    async fn unknown_authorization_is_rejected() {
        let req = test::TestRequest::post()
            .header("Authorization", "Invalid")
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[actix_rt::test]
    async fn invalid_base64_password_is_rejected() {
        let req = test::TestRequest::post()
            .header("Authorization", "Basic invalid")
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[actix_rt::test]
    async fn invalid_utf8_password_is_rejected() {
        let req = test::TestRequest::post()
            .header("Authorization", "Basic changeme")
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[actix_rt::test]
    async fn missing_password_is_rejected() {
        let req = test::TestRequest::post()
            .header(
                "Authorization",
                "Basic ".to_string() + &base64::encode("username".as_bytes()),
            )
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(ProtocolError::InvalidClient),
            response.error
        );
    }

    #[actix_rt::test]
    async fn issue_valid_token_for_correct_password() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert_eq!(None, response.refresh_token);
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn issue_valid_token_with_id_token_for_correct_password() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let redirect_uri = "fdsa".to_string();
        let auth_code_store = build_test_auth_code_store();
        let auth_code = auth_code_store.get_authorization_code(
            CONFIDENTIAL_CLIENT,
            USER,
            &redirect_uri,
            Local::now(),
        );
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert_eq!(None, response.refresh_token);
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }
}
