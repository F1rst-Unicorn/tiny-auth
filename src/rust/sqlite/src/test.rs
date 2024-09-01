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
use crate::inject::sqlite_store;
use crate::store::SqliteStore;
use chrono::{Duration, Local};
use std::sync::Arc;
use test_log::test;
use tiny_auth_business::store::{
    AuthorizationCodeRequest, AuthorizationCodeStore, ValidationRequest,
};

#[test(tokio::test)]
async fn connecting_works() {
    store().await;
}

#[test(tokio::test)]
async fn auth_code_storing_works() {
    let request = AuthorizationCodeRequest {
        client_id: "tiny-auth-frontend",
        user: "john",
        redirect_uri: "http://localhost:8088/oidc-login-redirect",
        scope: "openid",
        insertion_time: Local::now(),
        authentication_time: Local::now(),
        nonce: Some("nonce".to_string()),
        pkce_challenge: Some((&("a".repeat(44))).try_into().unwrap()),
    };
    let uut = store().await;

    let code = uut.get_authorization_code(request.clone()).await.unwrap();
    let delta = Duration::minutes(1);
    let response = uut
        .validate(ValidationRequest {
            client_id: request.client_id,
            authorization_code: &code,
            validation_time: request.insertion_time.clone() + delta,
        })
        .await;

    assert!(response.is_ok());
    let response = response.unwrap();
    assert_eq!(request.redirect_uri, response.redirect_uri);
    assert_eq!(delta, response.stored_duration);
    assert_eq!(request.user, response.username);
    assert_eq!(request.scope, response.scopes);
    assert_eq!(request.authentication_time, response.authentication_time);
    assert_eq!(request.nonce, response.nonce);
    assert_eq!(request.pkce_challenge, response.pkce_challenge);
}

#[test(tokio::test)]
async fn auth_code_can_be_used_only_once() {
    let request = AuthorizationCodeRequest {
        client_id: "tiny-auth-frontend",
        user: "john",
        redirect_uri: "http://localhost:8088/oidc-login-redirect",
        scope: "openid",
        insertion_time: Local::now(),
        authentication_time: Local::now(),
        nonce: Some("nonce".to_string()),
        pkce_challenge: Some((&("a".repeat(44))).try_into().unwrap()),
    };
    let uut = store().await;
    let code = uut.get_authorization_code(request.clone()).await.unwrap();
    let delta = Duration::minutes(1);
    let response = uut
        .validate(ValidationRequest {
            client_id: request.client_id,
            authorization_code: &code,
            validation_time: request.insertion_time.clone() + delta,
        })
        .await;
    assert!(response.is_ok());

    let response = uut
        .validate(ValidationRequest {
            client_id: request.client_id,
            authorization_code: &code,
            validation_time: request.insertion_time.clone() + delta,
        })
        .await;

    assert!(response.is_err());
}

async fn store() -> Arc<SqliteStore> {
    sqlite_store(&(env!("CARGO_MANIFEST_DIR").to_string() + "/../../sql/sqlite/build/db.sqlite"))
        .await
        .unwrap()
}
