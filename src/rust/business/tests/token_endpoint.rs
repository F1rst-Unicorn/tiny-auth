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

#![expect(clippy::unwrap_used)] // this is test code

use chrono::{Duration, Local};
use pretty_assertions::assert_eq;
use std::sync::Arc;
use test_log::test;
use tiny_auth_business::oauth2::GrantType;
use tiny_auth_business::store::{
    AuthorizationCodeRequest, AuthorizationCodeStore, AUTH_CODE_LIFE_TIME,
};
use tiny_auth_business::token::EncodedRefreshToken;
use tiny_auth_business::token_endpoint::inject;
use tiny_auth_business::token_endpoint::{Error, Handler, Request};
use tiny_auth_test_fixtures::authenticator::authenticator;
use tiny_auth_test_fixtures::data::client::CONFIDENTIAL_CLIENT;
use tiny_auth_test_fixtures::data::client::PUBLIC_CLIENT;
use tiny_auth_test_fixtures::store::auth_code_store::build_test_auth_code_store;
use tiny_auth_test_fixtures::store::client_store::build_test_client_store;
use tiny_auth_test_fixtures::store::client_store::UNKNOWN_CLIENT_ID;
use tiny_auth_test_fixtures::store::scope_store::build_test_scope_store;
use tiny_auth_test_fixtures::store::user_store::build_test_user_store;
use tiny_auth_test_fixtures::store::user_store::USER;
use tiny_auth_test_fixtures::token::build_test_issuer_config;
use tiny_auth_test_fixtures::token::build_test_token_creator;
use tiny_auth_test_fixtures::token::build_test_token_validator;
use url::Url;

#[test(tokio::test)]
async fn missing_redirect_uri_is_rejected() {
    let request = Request::default();

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::MissingRedirectUri), response);
}

#[test(tokio::test)]
async fn missing_code_is_rejected() {
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        redirect_uri: Some(Url::parse("http://localhost/client").unwrap()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::MissingAuthorizationCode), response);
}

#[test(tokio::test)]
async fn missing_client_id_is_rejected() {
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some("fdsa".to_owned()),
        redirect_uri: Some(Url::parse("http://localhost/client").unwrap()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::MissingClientId), response);
}

#[test(tokio::test)]
async fn unknown_client_is_rejected() {
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some("fdsa".to_owned()),
        redirect_uri: Some(Url::parse("http://localhost/client").unwrap()),
        client_id: Some(UNKNOWN_CLIENT_ID.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::WrongClientIdOrPassword), response);
}

#[test(tokio::test)]
async fn unknown_auth_code_is_rejected() {
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some("fdsa".to_owned()),
        redirect_uri: Some(Url::parse("http://localhost/client").unwrap()),
        client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::InvalidAuthorizationCode), response);
}

#[test(tokio::test)]
async fn wrong_redirect_uri_is_rejected() {
    let redirect_uri = Url::parse("http://localhost/client").unwrap();
    let auth_code_store = build_test_auth_code_store();
    let auth_code = auth_code_store
        .get_authorization_code(AuthorizationCodeRequest {
            client_id: &PUBLIC_CLIENT.client_id,
            user: USER,
            redirect_uri: &redirect_uri,
            scope: "",
            insertion_time: Local::now(),
            authentication_time: Local::now(),
            nonce: Some("nonce".to_owned()),
            pkce_challenge: None,
        })
        .await
        .unwrap();
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some(auth_code + "/wrong"),
        redirect_uri: Some(redirect_uri),
        client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
        ..Request::default()
    };

    let response = uut_with_auth_code_store(auth_code_store)
        .grant_tokens(request)
        .await;

    assert_eq!(Err(Error::InvalidAuthorizationCode), response);
}

#[test(tokio::test)]
async fn expired_code_is_rejected() {
    let redirect_uri = Url::parse("http://localhost/client").unwrap();
    let auth_code_store = build_test_auth_code_store();
    let creation_time = Local::now() - Duration::minutes(2 * AUTH_CODE_LIFE_TIME);
    let auth_code = auth_code_store
        .get_authorization_code(AuthorizationCodeRequest {
            client_id: PUBLIC_CLIENT.client_id.as_str(),
            user: USER,
            redirect_uri: &redirect_uri,
            scope: "",
            insertion_time: creation_time,
            authentication_time: Local::now(),
            nonce: Some("nonce".to_owned()),
            pkce_challenge: None,
        })
        .await
        .unwrap();
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some(auth_code),
        redirect_uri: Some(redirect_uri),
        client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
        ..Request::default()
    };

    let response = uut_with_auth_code_store(auth_code_store)
        .grant_tokens(request)
        .await;

    assert_eq!(Err(Error::InvalidAuthorizationCode), response);
}

#[test(tokio::test)]
async fn valid_token_is_issued() {
    let redirect_uri = Url::parse("http://localhost/client").unwrap();
    let auth_code_store = build_test_auth_code_store();
    let auth_code = auth_code_store
        .get_authorization_code(AuthorizationCodeRequest {
            client_id: PUBLIC_CLIENT.client_id.as_str(),
            user: USER,
            redirect_uri: &redirect_uri,
            scope: "",
            insertion_time: Local::now(),
            authentication_time: Local::now(),
            nonce: Some("nonce".to_owned()),
            pkce_challenge: None,
        })
        .await
        .unwrap();
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some(auth_code),
        redirect_uri: Some(redirect_uri),
        client_id: Some(PUBLIC_CLIENT.client_id.to_owned()),
        ..Request::default()
    };

    let response = uut_with_auth_code_store(auth_code_store)
        .grant_tokens(request)
        .await;

    let validator = build_test_token_validator();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(validator.validate_access_token(response.0).is_some());
    assert!(validator.validate_id_token(response.1).is_some());
    assert!(response.2.is_none());
}

#[test(tokio::test)]
async fn confidential_client_without_basic_auth_is_rejected() {
    let redirect_uri = Url::parse("http://localhost/client").unwrap();
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some("fdsa".to_owned()),
        redirect_uri: Some(redirect_uri),
        client_id: Some(CONFIDENTIAL_CLIENT.client_id.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::ConfidentialClientMustAuthenticate), response);
}

#[test(tokio::test)]
async fn issue_valid_token_for_correct_password() {
    let redirect_uri = Url::parse("http://localhost/client").unwrap();
    let auth_code_store = build_test_auth_code_store();
    let auth_code = auth_code_store
        .get_authorization_code(AuthorizationCodeRequest {
            client_id: &CONFIDENTIAL_CLIENT.client_id,
            user: USER,
            redirect_uri: &redirect_uri,
            scope: "",
            insertion_time: Local::now(),
            authentication_time: Local::now(),
            nonce: Some("nonce".to_owned()),
            pkce_challenge: None,
        })
        .await
        .unwrap();
    let request = Request {
        grant_type: GrantType::AuthorizationCode,
        code: Some(auth_code),
        redirect_uri: Some(redirect_uri),
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        ..Request::default()
    };

    let response = uut_with_auth_code_store(auth_code_store)
        .grant_tokens(request)
        .await;

    let validator = build_test_token_validator();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(validator.validate_access_token(response.0).is_some());
    assert!(validator.validate_id_token(response.1).is_some());
    assert!(response.2.is_some());
    let refresh_token = validator.validate_refresh_token(response.2.unwrap());
    assert!(refresh_token.is_some());
    assert_eq!("nonce".to_owned(), refresh_token.unwrap().nonce);
}

#[test(tokio::test)]
async fn public_client_cannot_get_access_token_for_itself() {
    let request = Request {
        grant_type: GrantType::ClientCredentials,
        basic_authentication: Some((
            PUBLIC_CLIENT.client_id.to_owned(),
            PUBLIC_CLIENT.client_id.to_owned(),
        )),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::InvalidAuthorizationHeader), response);
}

#[test(tokio::test)]
async fn confidential_client_gets_access_token_for_itself() {
    let request = Request {
        grant_type: GrantType::ClientCredentials,
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    let validator = build_test_token_validator();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(validator.validate_access_token(response.0).is_some());
    assert!(validator.validate_id_token(response.1).is_some());
    assert!(response.2.is_some());
    assert!(validator
        .validate_refresh_token(response.2.unwrap())
        .is_some());
}

#[test(tokio::test)]
async fn missing_username_is_rejected_with_password_grant() {
    let request = Request {
        grant_type: GrantType::Password,
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        password: Some(USER.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::MissingUsername), response);
}

#[test(tokio::test)]
async fn missing_password_is_rejected_with_password_grant() {
    let request = Request {
        grant_type: GrantType::Password,
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        username: Some(USER.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::MissingPassword), response);
}

#[test(tokio::test)]
async fn public_client_cannot_use_password_grant() {
    let request = Request {
        grant_type: GrantType::Password,
        basic_authentication: Some((
            PUBLIC_CLIENT.client_id.to_owned(),
            PUBLIC_CLIENT.client_id.to_owned(),
        )),
        username: Some(USER.to_owned()),
        password: Some(USER.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::InvalidAuthorizationHeader), response);
}

#[test(tokio::test)]
async fn confidential_client_can_use_password_grant() {
    let request = Request {
        grant_type: GrantType::Password,
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        username: Some(USER.to_owned()),
        password: Some(USER.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    let validator = build_test_token_validator();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(validator.validate_access_token(response.0).is_some());
    assert!(validator.validate_id_token(response.1).is_some());
    assert!(response.2.is_some());
    assert!(validator
        .validate_refresh_token(response.2.unwrap())
        .is_some());
}

#[test(tokio::test)]
async fn missing_refresh_token_is_rejected() {
    let request = Request {
        grant_type: GrantType::RefreshToken,
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::MissingRefreshToken), response);
}

#[test(tokio::test)]
async fn invalid_refresh_token_is_rejected() {
    let request = Request {
        grant_type: GrantType::RefreshToken,
        refresh_token: Some(unsafe { EncodedRefreshToken::from_parts("invalid".into()) }),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::InvalidRefreshToken), response);
}

#[test(tokio::test)]
async fn invalid_client_credentials_with_refresh_token_are_rejected() {
    let request = Request {
        grant_type: GrantType::RefreshToken,
        basic_authentication: Some((CONFIDENTIAL_CLIENT.client_id.to_owned(), "wrong".to_owned())),
        refresh_token: Some(build_refresh_token(&CONFIDENTIAL_CLIENT.client_id).await),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::WrongClientIdOrPassword), response);
}

#[test(tokio::test)]
async fn refresh_token_from_different_client_is_rejected() {
    let request = Request {
        grant_type: GrantType::RefreshToken,
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        refresh_token: Some(build_refresh_token(&PUBLIC_CLIENT.client_id).await),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    assert_eq!(Err(Error::InvalidRefreshToken), response);
}

#[test(tokio::test)]
async fn successful_refresh_token_authentication() {
    let request = Request {
        grant_type: GrantType::RefreshToken,
        basic_authentication: Some((
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
            CONFIDENTIAL_CLIENT.client_id.to_owned(),
        )),
        refresh_token: Some(build_refresh_token(&CONFIDENTIAL_CLIENT.client_id).await),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    let validator = build_test_token_validator();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(validator.validate_access_token(response.0).is_some());
    assert!(validator.validate_id_token(response.1).is_some());
    assert!(response.2.is_some());
    assert!(validator
        .validate_refresh_token(response.2.unwrap())
        .is_some());
}

#[test(tokio::test)]
async fn successful_authentication_with_secret_as_post_parameter() {
    let request = Request {
        grant_type: GrantType::RefreshToken,
        refresh_token: Some(build_refresh_token(&CONFIDENTIAL_CLIENT.client_id).await),
        client_id: Some(CONFIDENTIAL_CLIENT.client_id.to_owned()),
        client_secret: Some(CONFIDENTIAL_CLIENT.client_id.to_owned()),
        ..Request::default()
    };

    let response = uut().grant_tokens(request).await;

    let validator = build_test_token_validator();
    assert!(response.is_ok());
    let response = response.unwrap();
    assert!(validator.validate_access_token(response.0).is_some());
    assert!(validator.validate_id_token(response.1).is_some());
    assert!(response.2.is_some());
    assert!(validator
        .validate_refresh_token(response.2.unwrap())
        .is_some());
}

fn uut() -> Handler {
    uut_with_auth_code_store(build_test_auth_code_store())
}

fn uut_with_auth_code_store(auth_code_store: Arc<dyn AuthorizationCodeStore>) -> Handler {
    inject::handler(
        build_test_client_store(),
        build_test_user_store(),
        auth_code_store.clone(),
        build_test_token_creator(),
        Arc::new(authenticator()),
        Arc::new(build_test_token_validator()),
        build_test_scope_store(),
        build_test_issuer_config(),
    )
}

async fn build_refresh_token(client_id: &str) -> EncodedRefreshToken {
    let token_creator = build_test_token_creator();
    let mut token =
        token_creator.build_refresh_token(Local::now().timestamp(), &[], USER, client_id, 0);
    token.set_nonce(Some("nonce".to_owned()));
    token_creator.finalize_refresh_token(token).unwrap()
}
