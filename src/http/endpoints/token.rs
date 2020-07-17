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
use super::parse_basic_authorization;
use crate::business::token::TokenCreator;
use crate::business::token::TokenValidator;
use crate::business::Authenticator;
use crate::domain::user::User;
use crate::domain::Client;
use crate::domain::RefreshToken;
use crate::domain::Token;
use crate::http::endpoints::render_json_error;
use crate::protocol::oauth2;
use crate::protocol::oauth2::ClientType;
use crate::protocol::oauth2::GrantType;
use crate::protocol::oidc::ProtocolError;
use crate::store::AuthorizationCodeStore;
use crate::store::ClientStore;
use crate::store::UserStore;
use crate::store::AUTH_CODE_LIFE_TIME;

use std::convert::TryInto;
use std::sync::Arc;

use actix_web::web;
use actix_web::HttpRequest;
use actix_web::HttpResponse;

use serde_derive::Deserialize;
use serde_derive::Serialize;

use chrono::offset::Local;
use chrono::Duration;

use log::debug;

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

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    scope: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    username: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    password: Option<String>,

    #[serde(default)]
    #[serde(deserialize_with = "deserialise_empty_as_none")]
    refresh_token: Option<String>,
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

#[allow(clippy::too_many_arguments)]
pub async fn post(
    headers: HttpRequest,
    request: web::Form<Request>,
    client_store: web::Data<Arc<dyn ClientStore>>,
    user_store: web::Data<Arc<dyn UserStore>>,
    auth_code_store: web::Data<Arc<dyn AuthorizationCodeStore>>,
    token_creator: web::Data<TokenCreator>,
    authenticator: web::Data<Authenticator>,
    token_validator: web::Data<TokenValidator>,
) -> HttpResponse {
    let grant_type = match &request.grant_type {
        None => {
            return render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing parameter grant_type",
            );
        }
        Some(grant_type) => grant_type,
    };

    let generate_refresh_token;

    let token: Token = match grant_type {
        GrantType::RefreshToken => {
            generate_refresh_token = true;
            match grant_with_refresh_token(
                headers,
                request,
                client_store,
                authenticator,
                token_validator,
            )
            .await
            {
                Err(e) => return e,
                Ok(t) => t,
            }
        }
        _ => {
            let result = match grant_type {
                GrantType::AuthorizationCode => {
                    grant_with_authorization_code(
                        headers,
                        request,
                        client_store,
                        user_store,
                        auth_code_store,
                        authenticator,
                    )
                    .await
                }
                GrantType::ClientCredentials => {
                    grant_with_client_credentials(headers, client_store, authenticator).await
                }
                GrantType::Password => {
                    grant_with_password(headers, request, client_store, authenticator).await
                }
                _ => {
                    return render_json_error(
                        ProtocolError::OAuth2(oauth2::ProtocolError::UnsupportedGrantType),
                        "invalid grant_type",
                    );
                }
            };

            let (user, client, auth_time) = match result {
                Err(r) => return r,
                Ok(x) => x,
            };

            generate_refresh_token = match client.client_type {
                ClientType::Confidential { .. } => true,
                _ => false,
            };

            Token::build(
                &user,
                &client,
                Local::now(),
                Duration::minutes(1),
                auth_time,
            )
        }
    };

    let encoded_token = match token_creator.create(token.clone()) {
        Err(e) => {
            debug!("failed to encode token: {}", e);
            return render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::ServerError),
                "token encoding failed",
            );
        }
        Ok(token) => token,
    };
    let refresh_token = if generate_refresh_token {
        match token_creator.create_refresh_token(RefreshToken::from(
            token,
            Duration::minutes(1),
            Vec::new(),
        )) {
            Err(e) => {
                debug!("failed to encode refresh token: {}", e);
                return render_json_error(
                    ProtocolError::OAuth2(oauth2::ProtocolError::ServerError),
                    "refresh token encoding failed",
                );
            }
            token => token.ok(),
        }
    } else {
        None
    };

    HttpResponse::Ok().json(Response {
        access_token: encoded_token.clone(),
        token_type: "bearer".to_string(),
        expires_in: Some(60),
        refresh_token,
        scope: None,
        id_token: Some(encoded_token),
    })
}

async fn grant_with_authorization_code(
    headers: HttpRequest,
    request: web::Form<Request>,
    client_store: web::Data<Arc<dyn ClientStore>>,
    user_store: web::Data<Arc<dyn UserStore>>,
    auth_code_store: web::Data<Arc<dyn AuthorizationCodeStore>>,
    authenticator: web::Data<Authenticator>,
) -> Result<(User, Client, i64), HttpResponse> {
    if request.redirect_uri.is_none() {
        return Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing parameter redirect_uri",
        ));
    }

    if request.code.is_none() {
        return Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
            "Missing parameter code",
        ));
    }

    let client = match authenticate_client(headers, (*client_store).clone(), authenticator) {
        Err(_) => {
            let client_id = match &request.client_id {
                None => {
                    return Err(render_json_error(
                        ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                        "Missing parameter client_id",
                    ))
                }
                Some(client_id) => client_id,
            };
            let client = match client_store.get(&client_id) {
                None => {
                    debug!("client '{}' not found", client_id);
                    return Err(render_json_error(
                        ProtocolError::OAuth2(oauth2::ProtocolError::UnauthorizedClient),
                        "client id or password wrong",
                    ));
                }
                Some(client) => client,
            };

            if let ClientType::Confidential { .. } = client.client_type {
                return Err(render_json_error(
                    ProtocolError::OAuth2(oauth2::ProtocolError::UnauthorizedClient),
                    "Confidential client has to authenticate",
                ));
            }

            client
        }
        Ok(client) => client,
    };

    let code = request.code.as_ref().unwrap();
    let record = match auth_code_store
        .validate(&client.client_id, &code, Local::now())
        .await
    {
        None => {
            debug!(
                "No authorization code found for client '{}' with code '{}'",
                &client.client_id, code
            );
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                "Invalid code",
            ));
        }
        Some(record) => record,
    };

    if &record.redirect_uri != request.redirect_uri.as_ref().unwrap() {
        debug!("redirect_uri is wrong");
        return Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
            "Invalid code",
        ));
    }

    if record.stored_duration > Duration::minutes(AUTH_CODE_LIFE_TIME) {
        debug!("code has expired");
        return Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
            "Invalid code",
        ));
    }

    let user = match user_store.get(&record.username) {
        None => {
            debug!("user {} not found", record.username);
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                "User not found",
            ));
        }
        Some(user) => user,
    };

    Ok((user, client, record.auth_time.timestamp()))
}

async fn grant_with_client_credentials(
    headers: HttpRequest,
    client_store: web::Data<Arc<dyn ClientStore>>,
    authenticator: web::Data<Authenticator>,
) -> Result<(User, Client, i64), HttpResponse> {
    let client = authenticate_client(headers, (*client_store).clone(), authenticator)?;
    Ok((
        client.clone().try_into().unwrap(),
        client,
        Local::now().timestamp(),
    ))
}

async fn grant_with_password(
    headers: HttpRequest,
    request: web::Form<Request>,
    client_store: web::Data<Arc<dyn ClientStore>>,
    authenticator: web::Data<Authenticator>,
) -> Result<(User, Client, i64), HttpResponse> {
    let username = match &request.username {
        None => {
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing username",
            ))
        }
        Some(username) => username,
    };

    let password = match &request.password {
        None => {
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing password",
            ))
        }
        Some(password) => password,
    };

    if headers.headers().get("Authorization").is_some() {
        let client = authenticate_client(headers, (*client_store).clone(), authenticator.clone())?;

        let user = match authenticator.authenticate_user(&username, &password) {
            None => {
                return Err(render_json_error(
                    ProtocolError::OAuth2(oauth2::ProtocolError::InvalidGrant),
                    "usernmae or password wrong",
                ))
            }
            Some(user) => user,
        };

        Ok((user, client, Local::now().timestamp()))
    } else {
        Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
            "Missing authorization header",
        ))
    }
}

async fn grant_with_refresh_token(
    headers: HttpRequest,
    request: web::Form<Request>,
    client_store: web::Data<Arc<dyn ClientStore>>,
    authenticator: web::Data<Authenticator>,
    validator: web::Data<TokenValidator>,
) -> Result<Token, HttpResponse> {
    let raw_token = match &request.refresh_token {
        None => {
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidRequest),
                "Missing refresh token",
            ));
        }
        Some(token) => token,
    };

    let refresh_token = match validator.validate::<RefreshToken>(&raw_token) {
        None => {
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::UnauthorizedClient),
                "Invalid refresh token",
            ));
        }
        Some(token) => token,
    };

    authenticate_client(headers, (*client_store).clone(), authenticator)?;

    let mut token = refresh_token.access_token;
    token.renew(Local::now(), Duration::minutes(1));
    Ok(token)
}

fn authenticate_client(
    headers: HttpRequest,
    client_store: Arc<Arc<dyn ClientStore>>,
    authenticator: web::Data<Authenticator>,
) -> Result<Client, HttpResponse> {
    let (client_name, password) = match headers.headers().get("Authorization") {
        Some(value) => match parse_basic_authorization(value) {
            Some(x) => x,
            None => {
                return Err(render_json_error(
                    ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                    "Invalid authorization header",
                ));
            }
        },
        None => {
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                "Missing authorization header",
            ));
        }
    };

    let client = match client_store.get(&client_name) {
        None => {
            debug!("Client '{}' not found", client_name);
            return Err(render_json_error(
                ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
                "client id or password wrong",
            ));
        }
        Some(c) => c,
    };

    if let ClientType::Public = client.client_type {
        debug!("tried to authenticate public client");
        return Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
            "Invalid authorization header",
        ));
    }

    if !authenticator.authenticate_client(&client, &password) {
        debug!("password for client '{}' was wrong", client_name);
        Err(render_json_error(
            ProtocolError::OAuth2(oauth2::ProtocolError::InvalidClient),
            "client id or password wrong",
        ))
    } else {
        Ok(client)
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
    use crate::http::state::tests::build_test_authenticator;
    use crate::http::state::tests::build_test_client_store;
    use crate::http::state::tests::build_test_token_creator;
    use crate::http::state::tests::build_test_token_issuer;
    use crate::http::state::tests::build_test_token_validator;
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
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
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
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                PUBLIC_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri + "/wrong"),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                PUBLIC_CLIENT,
                USER,
                &redirect_uri,
                creation_time,
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                PUBLIC_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(PUBLIC_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        let response = read_response::<ErrorResponse>(resp).await;
        assert_eq!(
            OidcError::from(oauth2::ProtocolError::UnauthorizedClient),
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
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
        let auth_code = auth_code_store
            .get_authorization_code(
                CONFIDENTIAL_CLIENT,
                USER,
                &redirect_uri,
                Local::now(),
                Local::now(),
            )
            .await;
        let form = Form(Request {
            grant_type: Some(GrantType::AuthorizationCode),
            code: Some(auth_code),
            client_id: Some(CONFIDENTIAL_CLIENT.to_string()),
            redirect_uri: Some(redirect_uri),
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn public_client_cannot_get_access_token() {
        let auth = PUBLIC_CLIENT.to_string() + ":" + PUBLIC_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::ClientCredentials),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
    async fn confidential_client_gets_access_token() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::ClientCredentials),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn missing_username_is_rejected() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: Some(USER.to_string()),
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
    async fn missing_password_is_rejected_with_password_grant() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: Some(USER.to_string()),
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
    async fn public_client_cannot_use_password_grant() {
        let auth = PUBLIC_CLIENT.to_string() + ":" + PUBLIC_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
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
    async fn confidential_client_can_use_password_grant() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::Password),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: Some(USER.to_string()),
            password: Some(USER.to_string()),
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }

    #[actix_rt::test]
    async fn missing_refresh_token_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: None,
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn invalid_refresh_token_is_rejected() {
        let req = test::TestRequest::post().to_http_request();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some("dummy".to_string()),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            build_test_auth_code_store(),
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn invalid_client_credentials_with_refresh_token_are_rejected() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":wrong";
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();

        let token_creator = build_test_token_creator();
        let token = Token::build(
            &build_test_user_store().get(USER).unwrap(),
            &build_test_client_store().get(CONFIDENTIAL_CLIENT).unwrap(),
            Local::now(),
            Duration::minutes(3),
            0,
        );
        let refresh_token = token_creator
            .create_refresh_token(RefreshToken::from(token, Duration::minutes(1), Vec::new()))
            .unwrap();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some(refresh_token),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn successful_refresh_token_authentication() {
        let auth = CONFIDENTIAL_CLIENT.to_string() + ":" + CONFIDENTIAL_CLIENT;
        let encoded_auth = base64::encode(auth);
        let auth_code_store = build_test_auth_code_store();
        let req = test::TestRequest::post()
            .header("Authorization", "Basic ".to_string() + &encoded_auth)
            .to_http_request();

        let token_creator = build_test_token_creator();
        let mut token = Token::build(
            &build_test_user_store().get(USER).unwrap(),
            &build_test_client_store().get(CONFIDENTIAL_CLIENT).unwrap(),
            Local::now(),
            Duration::minutes(3),
            0,
        );
        token.set_issuer(&build_test_token_issuer());
        let refresh_token = token_creator
            .create_refresh_token(RefreshToken::from(token, Duration::minutes(1), Vec::new()))
            .unwrap();
        let form = Form(Request {
            grant_type: Some(GrantType::RefreshToken),
            code: None,
            client_id: None,
            redirect_uri: None,
            scope: None,
            username: None,
            password: None,
            refresh_token: Some(refresh_token),
        });

        let resp = post(
            req,
            form,
            build_test_client_store(),
            build_test_user_store(),
            auth_code_store,
            build_test_token_creator(),
            build_test_authenticator(),
            build_test_token_validator(),
        )
        .await;

        assert_eq!(resp.status(), http::StatusCode::OK);
        let response = read_response::<Response>(resp).await;
        assert!(!response.access_token.is_empty());
        assert_eq!("bearer".to_string(), response.token_type);
        assert_eq!(Some(60), response.expires_in);
        assert!(response.refresh_token.iter().any(|v| !v.is_empty()));
        assert_eq!(None, response.scope);
        assert!(!response.id_token.unwrap().is_empty());
    }
}
