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

use crate::pkce::CodeChallenge;
use crate::store::AuthCodeValidationError::NotFound;
use crate::store::AuthorizationCodeStore;
use crate::store::ValidationRequest;
use crate::store::{AuthCodeError, AuthorizationCodeRequest};
use crate::store::{AuthCodeValidationError, AuthorizationCodeResponse};
use async_trait::async_trait;
use chrono::DateTime;
use chrono::Duration;
use chrono::Local;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, instrument, trace, Level};
use url::Url;

#[derive(PartialEq, Eq, Hash)]
struct AuthCodeKey {
    client_id: String,

    authorization_code: String,
}

struct AuthCodeValue {
    redirect_uri: Url,

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

pub async fn auth_code_clean_job(store: Arc<dyn AuthorizationCodeStore>) {
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
    #[instrument(skip_all, ret(level = Level::DEBUG))]
    async fn get_authorization_code<'a>(
        &self,
        request: AuthorizationCodeRequest<'a>,
    ) -> Result<String, AuthCodeError> {
        debug!("issuing authorization code");
        let mut store = self.store.write().await;
        let mut key = AuthCodeKey {
            client_id: request.client_id.to_owned(),
            authorization_code: "".to_owned(),
        };

        loop {
            let auth_code = generate_random_string(32);
            key.authorization_code.clone_from(&auth_code);

            if store.get(&key).is_none() {
                store.insert(
                    key,
                    AuthCodeValue {
                        redirect_uri: request.redirect_uri.to_owned(),
                        user: request.user.to_owned(),
                        scope: request.scope.to_owned(),
                        insertion_time: request.insertion_time,
                        authentication_time: request.authentication_time,
                        nonce: request.nonce,
                        pkce_challenge: request.pkce_challenge,
                    },
                );
                break Ok(auth_code);
            }
        }
    }

    async fn validate<'a>(
        &self,
        request: ValidationRequest<'a>,
    ) -> Result<AuthorizationCodeResponse, AuthCodeValidationError> {
        let mut store = self.store.write().await;

        let value = store
            .remove(&AuthCodeKey {
                client_id: request.client_id.to_owned(),
                authorization_code: request.authorization_code.to_owned(),
            })
            .ok_or(NotFound)?;

        Ok(AuthorizationCodeResponse {
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

    async fn clear_expired_codes(&self, now: DateTime<Local>, validity: Duration) {
        let mut store = self.store.write().await;
        store.retain(|_, v| now.signed_duration_since(v.insertion_time) <= validity);
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
    use chrono::{TimeDelta, TimeZone};
    use pretty_assertions::assert_eq;
    use rstest::{fixture, rstest};
    use test_log::test;

    #[rstest]
    #[test(tokio::test)]
    async fn successful_validation_works(
        uut: MemoryAuthorizationCodeStore,
        now: DateTime<Local>,
        duration: TimeDelta,
        redirect_uri: Url,
    ) {
        let auth_code = uut
            .get_authorization_code(auth_code_request(now, &redirect_uri))
            .await
            .unwrap();

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: now + duration,
            })
            .await;

        assert!(output.is_ok());
        let output = output.unwrap();
        assert_eq!(&redirect_uri, &output.redirect_uri);
        assert_eq!("user", &output.username);
        assert_eq!(duration, output.stored_duration);
        assert_eq!("", output.scopes);
    }

    #[rstest]
    #[test(tokio::test)]
    async fn expired_code_is_deleted(
        uut: MemoryAuthorizationCodeStore,
        now: DateTime<Local>,
        duration: TimeDelta,
        redirect_uri: Url,
    ) {
        let auth_code = uut
            .get_authorization_code(auth_code_request(now, &redirect_uri))
            .await
            .unwrap();
        uut.clear_expired_codes(now + duration + duration, duration)
            .await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: now + duration,
            })
            .await;

        assert!(matches!(output, Err(NotFound)));
    }

    #[rstest]
    #[test(tokio::test)]
    async fn code_still_works_at_sharp_expiration_time(
        uut: MemoryAuthorizationCodeStore,
        now: DateTime<Local>,
        duration: TimeDelta,
        redirect_uri: Url,
    ) {
        let auth_code = uut
            .get_authorization_code(auth_code_request(now, &redirect_uri))
            .await
            .unwrap();

        uut.clear_expired_codes(now + duration, duration).await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: now + duration,
            })
            .await;

        assert!(dbg!(&output).is_ok());
        let output = output.unwrap();
        assert_eq!(&redirect_uri, &output.redirect_uri);
        assert_eq!("user", &output.username);
        assert_eq!(duration, output.stored_duration);
        assert_eq!("", output.scopes);
    }

    #[rstest]
    #[test(tokio::test)]
    async fn code_past_expiration_date_doesnt_work_anymore(
        uut: MemoryAuthorizationCodeStore,
        now: DateTime<Local>,
        duration: TimeDelta,
        redirect_uri: Url,
    ) {
        let auth_code = uut
            .get_authorization_code(auth_code_request(now, &redirect_uri))
            .await
            .unwrap();
        uut.clear_expired_codes(now + duration + Duration::nanoseconds(1), duration)
            .await;

        let output = uut
            .validate(ValidationRequest {
                client_id: "client",
                authorization_code: &auth_code,
                validation_time: now + duration,
            })
            .await;

        assert!(output.is_err());
    }

    #[fixture]
    fn uut() -> MemoryAuthorizationCodeStore {
        MemoryAuthorizationCodeStore::default()
    }

    #[fixture]
    fn now() -> DateTime<Local> {
        Local.timestamp_opt(0, 0).unwrap()
    }

    #[fixture]
    fn duration() -> TimeDelta {
        Duration::minutes(1)
    }

    #[fixture]
    fn redirect_uri() -> Url {
        Url::parse("http://localhost/client").unwrap()
    }

    fn auth_code_request(now: DateTime<Local>, redirect_uri: &Url) -> AuthorizationCodeRequest {
        AuthorizationCodeRequest {
            client_id: "client",
            user: "user",
            redirect_uri,
            scope: "",
            insertion_time: now,
            authentication_time: now,
            nonce: Some("nonce".to_owned()),
            pkce_challenge: None,
        }
    }
}
