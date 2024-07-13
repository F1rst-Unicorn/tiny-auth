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

use crate::store::AuthorizationCodeRequest;
use crate::store::AuthorizationCodeResponse;
use crate::store::AuthorizationCodeStore;
use crate::store::ValidationRequest;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use tokio::sync::RwLock;
use tokio::time;

use chrono::DateTime;
use chrono::Duration;
use chrono::Local;

use crate::pkce::CodeChallenge;
use tracing::trace;

#[derive(PartialEq, Eq, Hash)]
struct AuthCodeKey {
    client_id: String,

    authorization_code: String,
}

struct AuthCodeValue {
    redirect_uri: String,

    user: String,

    scope: String,

    insertion_time: DateTime<Local>,

    authentication_time: DateTime<Local>,

    nonce: Option<String>,

    pkce_challenge: Option<CodeChallenge>,
}

pub struct MemoryAuthorizationCodeStore {
    store: Arc<RwLock<HashMap<AuthCodeKey, AuthCodeValue>>>,
}

impl Default for MemoryAuthorizationCodeStore {
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl MemoryAuthorizationCodeStore {
    async fn clear_expired_codes(&self, now: DateTime<Local>, validity: Duration) {
        let mut store = self.store.write().await;
        store.retain(|_, v| now.signed_duration_since(v.insertion_time) <= validity);
    }
}

pub async fn auth_code_clean_job(store: Arc<MemoryAuthorizationCodeStore>) {
    let mut clock = time::interval(time::Duration::from_secs(120));

    loop {
        clock.tick().await;
        trace!("Purging expired auth codes");
        store
            .clear_expired_codes(Local::now(), Duration::minutes(super::AUTH_CODE_LIFE_TIME))
            .await;
    }
}

#[async_trait]
impl AuthorizationCodeStore for MemoryAuthorizationCodeStore {
    async fn get_authorization_code<'a>(&self, request: AuthorizationCodeRequest<'a>) -> String {
        let mut store = self.store.write().await;
        let mut key = AuthCodeKey {
            client_id: request.client_id.to_string(),
            authorization_code: "".to_string(),
        };

        loop {
            let auth_code = generate_random_string(32);
            key.authorization_code.clone_from(&auth_code);

            if store.get(&key).is_none() {
                store.insert(
                    key,
                    AuthCodeValue {
                        redirect_uri: request.redirect_uri.to_string(),
                        user: request.user.to_string(),
                        scope: request.scope.to_string(),
                        insertion_time: request.insertion_time,
                        authentication_time: request.authentication_time,
                        nonce: request.nonce,
                        pkce_challenge: request.pkce_challenge,
                    },
                );
                break auth_code;
            }
        }
    }

    async fn validate<'a>(
        &self,
        request: ValidationRequest<'a>,
    ) -> Option<AuthorizationCodeResponse> {
        let mut store = self.store.write().await;

        let value = store.remove(&AuthCodeKey {
            client_id: request.client_id.to_string(),
            authorization_code: request.authorization_code.to_string(),
        })?;

        Some(AuthorizationCodeResponse {
            redirect_uri: value.redirect_uri.clone(),
            stored_duration: request
                .validation_time
                .signed_duration_since(value.insertion_time),
            username: value.user,
            scopes: value.scope,
            authentication_time: value.authentication_time,
            nonce: value.nonce,
            pkce_challenge: value.pkce_challenge,
        })
    }
}

pub fn generate_random_string(length: u32) -> String {
    let mut result = String::new();
    for _ in 0..length {
        let mut char = 'ö';
        while !char.is_ascii_alphanumeric() {
            char = rand::random::<u8>().into();
        }
        result.push(char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn successful_validation_works() {
        let uut = MemoryAuthorizationCodeStore::default();
        let date = Local::now();
        let duration = Duration::minutes(1);
        let auth_code = uut
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: "client",
                user: "user",
                redirect_uri: "redirect_uri",
                scope: "",
                insertion_time: date,
                authentication_time: date,
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: date + duration,
            })
            .await;

        assert!(output.is_some());
        let output = output.unwrap();
        assert_eq!("redirect_uri", &output.redirect_uri);
        assert_eq!("user", &output.username);
        assert_eq!(duration, output.stored_duration);
        assert_eq!("", output.scopes);
    }

    #[tokio::test]
    async fn expired_code_is_deleted() {
        let uut = MemoryAuthorizationCodeStore::default();
        let date = Local::now();
        let duration = Duration::minutes(1);
        let auth_code = uut
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: "client",
                user: "user",
                redirect_uri: "redirect_uri",
                scope: "",
                insertion_time: date,
                authentication_time: date,
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;

        uut.clear_expired_codes(date + duration + duration, duration)
            .await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: date + duration,
            })
            .await;

        assert!(output.is_none());
    }

    #[tokio::test]
    async fn code_still_works_at_sharp_expiration_time() {
        let uut = MemoryAuthorizationCodeStore::default();
        let date = Local::now();
        let duration = Duration::minutes(1);
        let auth_code = uut
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: "client",
                user: "user",
                redirect_uri: "redirect_uri",
                scope: "",
                insertion_time: date,
                authentication_time: date,
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;

        uut.clear_expired_codes(date + duration, duration).await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: date + duration,
            })
            .await;

        assert!(output.is_some());
        let output = output.unwrap();
        assert_eq!("redirect_uri", &output.redirect_uri);
        assert_eq!("user", &output.username);
        assert_eq!(duration, output.stored_duration);
        assert_eq!("", output.scopes);
    }

    #[tokio::test]
    async fn code_past_expiration_date_doesnt_work_anymore() {
        let uut = MemoryAuthorizationCodeStore::default();
        let date = Local::now();
        let duration = Duration::minutes(1);
        let auth_code = uut
            .get_authorization_code(AuthorizationCodeRequest {
                client_id: "client",
                user: "user",
                redirect_uri: "redirect_uri",
                scope: "",
                insertion_time: date,
                authentication_time: date,
                nonce: Some("nonce".to_string()),
                pkce_challenge: None,
            })
            .await;

        uut.clear_expired_codes(date + duration + Duration::nanoseconds(1), duration)
            .await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: date + duration,
            })
            .await;

        assert!(output.is_none());
    }
}
