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
use crate::data_assembler::{DataAssembler, QueryLoader};
use crate::inject::sqlite_store;
use crate::store::SqliteStore;
use chrono::{Duration, Local};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use test_log::test;
use tiny_auth_business::data_loader::DataLoader;
use tiny_auth_business::data_loader::Multiplicity::{ToMany, ToOne};
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::{InPlacePasswordStore, Password};
use tiny_auth_business::store::{
    AuthorizationCodeRequest, AuthorizationCodeStore, ClientStore, PasswordStore, UserStore,
    ValidationRequest,
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

#[test(tokio::test)]
async fn expired_auth_code_is_cleared() {
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
    let validity = Duration::minutes(1);

    uut.clear_expired_codes(
        request.insertion_time + validity + Duration::nanoseconds(1),
        validity,
    )
    .await;

    let response = uut
        .validate(ValidationRequest {
            client_id: request.client_id,
            authorization_code: &code,
            validation_time: request.insertion_time.clone(),
        })
        .await;
    assert!(response.is_err());
}

#[test(tokio::test)]
async fn non_expired_auth_code_is_retained() {
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
    let validity = Duration::minutes(1);

    uut.clear_expired_codes(
        request.insertion_time + validity - Duration::nanoseconds(1),
        validity,
    )
    .await;

    let response = uut
        .validate(ValidationRequest {
            client_id: request.client_id,
            authorization_code: &code,
            validation_time: request.insertion_time.clone(),
        })
        .await;
    assert!(response.is_ok());
}

#[test(tokio::test)]
async fn getting_user_works() {
    let uut = store().await;
    let key = "john";

    let mut actual = UserStore::get(&*uut, key).await.unwrap();

    assert_eq!(key, &actual.name);
    assert!(matches!(actual.password, Password::Sqlite { .. }));
    assert_eq!(
        BTreeSet::from_iter(vec!["openid".to_string(), "profile".to_string()]),
        actual
            .allowed_scopes
            .remove("tiny-auth-frontend")
            .unwrap_or_default()
    );
    assert_eq!(
        Some(Value::String(String::from("john@test.example"))),
        actual.attributes.remove("email")
    );
    assert_eq!(
        Some(Value::Number(1.into())),
        actual.attributes.remove("email_verified")
    );
    assert_eq!(
        Some(Value::Array(vec![])),
        actual.attributes.remove("picture")
    );
}

#[test(tokio::test)]
async fn getting_client_works() {
    let uut = store().await;
    let key = "tiny-auth-frontend";

    let actual = ClientStore::get(&*uut, key).await.unwrap();

    assert_eq!(key, &actual.client_id);
    assert!(matches!(actual.client_type, ClientType::Public));
    assert_eq!(
        BTreeSet::from_iter(vec![
            "address".to_string(),
            "email".to_string(),
            "phone".to_string(),
            "openid".to_string(),
            "profile".to_string()
        ]),
        actual.allowed_scopes
    );
    assert_eq!(
        vec![
            "http://localhost:8088/oidc-login-redirect".to_string(),
            "http://localhost:8088/oidc-login-redirect-silent".to_string()
        ],
        actual.redirect_uris
    );
}

#[test(tokio::test)]
async fn verifying_password_works() {
    let uut = store().await;
    let username = "john";
    let user = UserStore::get(&*uut, username).await.unwrap();

    let password_correct = PasswordStore::verify(&*uut, username, &user.password, "password")
        .await
        .unwrap();

    assert!(password_correct);
}

#[test(tokio::test)]
async fn wrong_password_is_rejected() {
    let uut = store().await;
    let username = "john";
    let user = UserStore::get(&*uut, username).await.unwrap();

    let password_correct = PasswordStore::verify(&*uut, username, &user.password, "wrong")
        .await
        .unwrap();

    assert!(!password_correct);
}

#[test(tokio::test)]
async fn data_from_documentation_example_works() {
    let uut = store().await;
    let username = "documentation_example";
    let user = UserStore::get(&*uut, username).await.unwrap();

    assert_eq!(
        json!({
            "name": username,
            "family_name": "",
            "gender": "",
            "given_name": "",
            "locale": "",
            "middle_name": "",
            "nickname": "",
            "profile": "",
            "preferred_username": "",
            "phone_number": "+123456789",
            "address": "",
            "password": 2,
            "picture": [],
            "birthday": 0.0,
            "email": "john@test.example",
            "email_verified": 1,
            "phone_number_verified": 1,
            "updated_at": user.attributes["updated_at"],
            "website": "",
            "zoneinfo": "",
            "sits_in": 1,
            "desk": {
                "material":"steel",
            },
            "building": {
                "street":"Lincoln Street",
                "meeting_rooms": [
                    {
                        "kind":"small",
                    },
                    {
                        "kind":"large",
                    },
                ],
            },
            "pets": [
                {
                    "type":"cat",
                },
                {
                    "type":"dog",
                },
            ],
        }),
        serde_json::to_value(user.attributes).unwrap()
    );
}

async fn store() -> Arc<SqliteStore> {
    sqlite_store(
        "sqlite",
        &(env!("CARGO_MANIFEST_DIR").to_string() + "/../../sql/sqlite/build/unittests.sqlite"),
        Arc::new(InPlacePasswordStore {
            pepper: "x5ePiX0TmUF2HzuraKuab9exzumu2sO54bnlVhgCS5AAXxqyhSSuHbCiUmx0FxmjZH9Gb2obp0ff2imMS6z40Qcc".to_string(),
        }),
        DataAssembler::new([
            QueryLoader::new(
                DataLoader::new("desk".to_string(), "/user/desk".try_into().unwrap(), ToOne),
                "select id as tiny_auth_id, assigned_to as tiny_auth_assigned_to, material \
                from test_data_desk".to_string(),
                String::default()),
            QueryLoader::new(
                DataLoader::new("building".to_string(), "/user/building".try_into().unwrap(), ToOne),
                "select u.sits_in as tiny_auth_id, u.id as tiny_auth_assigned_to, b.street
                from tiny_auth_user u
                join test_data_building b on b.id = u.sits_in".to_string(),
                String::default()),
            QueryLoader::new(
                DataLoader::new("pets".to_string(), "/user/pets".try_into().unwrap(), ToMany),
                "select id as tiny_auth_id, type from test_data_pet".to_string(),
                "select user as tiny_auth_assigned_to, pet as tiny_auth_id from test_data_pet_likes_user".to_string()),
            QueryLoader::new(
                DataLoader::new("meeting_rooms".to_string(), "/building/meeting_rooms".try_into().unwrap(), ToMany,),
                "select id as tiny_auth_id, contained_in as tiny_auth_assigned_to, kind \
                from test_data_meeting_room".to_string(),
                String::default()),
        ]),
        Default::default(),
    )
    .await
    .unwrap()
}
