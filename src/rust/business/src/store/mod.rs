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

pub mod memory;

use crate::client::Client;
use crate::client::Error as ClientError;
use crate::password::{Error as PasswordError, Password};
use crate::pkce::CodeChallenge;
use crate::scope::Scope;
use crate::user::{Error as UserError, User};
use async_trait::async_trait;
use chrono::DateTime;
use chrono::Duration;
use chrono::Local;
use futures_util::future::join_all;
use std::sync::Arc;
use tracing::{debug, info, instrument, Level};

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<User, UserError>;
}

pub struct MergingUserStore {
    stores: Vec<Arc<dyn UserStore>>,
}

impl From<Vec<Arc<dyn UserStore>>> for MergingUserStore {
    fn from(value: Vec<Arc<dyn UserStore>>) -> Self {
        Self { stores: value }
    }
}

#[async_trait]
impl UserStore for MergingUserStore {
    #[instrument(level = Level::DEBUG, name = "get_user", skip_all)]
    async fn get(&self, key: &str) -> Result<User, UserError> {
        let results: Vec<_> = join_all(self.stores.iter().map(|v| v.get(key)))
            .await
            .into_iter()
            .collect();

        if let Some(Err(error)) = results.iter().find(|v| {
            matches!(
                v,
                Err(UserError::BackendError | UserError::BackendErrorWithContext(_))
            )
        }) {
            return Err(error.clone());
        }

        results
            .into_iter()
            .filter_map(Result::ok)
            .reduce(User::merge)
            .inspect(|_| debug!("found"))
            .ok_or(UserError::NotFound)
    }
}

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Client, ClientError>;
}

pub struct MergingClientStore {
    stores: Vec<Arc<dyn ClientStore>>,
}

impl From<Vec<Arc<dyn ClientStore>>> for MergingClientStore {
    fn from(value: Vec<Arc<dyn ClientStore>>) -> Self {
        Self { stores: value }
    }
}

#[async_trait]
impl ClientStore for MergingClientStore {
    #[instrument(level = Level::DEBUG, name = "get_client", skip_all)]
    async fn get(&self, key: &str) -> Result<Client, ClientError> {
        let results: Vec<_> = join_all(self.stores.iter().map(|v| v.get(key)))
            .await
            .into_iter()
            .collect();

        if let Some(Err(error)) = results.iter().find(|v| {
            matches!(
                v,
                Err(ClientError::BackendError | ClientError::BackendErrorWithContext(_))
            )
        }) {
            return Err(error.clone());
        }

        results
            .into_iter()
            .filter_map(Result::ok)
            .reduce(Client::merge)
            .inspect(|_| debug!("found"))
            .ok_or(ClientError::NotFound)
    }
}

#[async_trait]
pub trait PasswordStore: Send + Sync {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, PasswordError>;
}

pub trait ScopeStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Scope>;

    fn get_all(&self, keys: &[String]) -> Vec<Scope> {
        keys.iter()
            .filter_map(|v| match self.get(v) {
                None => {
                    info!("requested unknown scope {}, ignoring", v);
                    None
                }
                s => s,
            })
            .collect()
    }

    fn get_scope_names(&self) -> Vec<String>;
}

/// Recommended lifetime is 10 minutes as of the [RFC](https://tools.ietf.org/html/rfc6749#section-4.1.2)
pub const AUTH_CODE_LIFE_TIME: i64 = 10;

pub struct AuthorizationCodeRequest<'a> {
    pub client_id: &'a str,

    pub user: &'a str,

    pub redirect_uri: &'a str,

    pub scope: &'a str,

    pub insertion_time: DateTime<Local>,

    pub authentication_time: DateTime<Local>,

    pub nonce: Option<String>,

    pub pkce_challenge: Option<CodeChallenge>,
}

pub struct AuthorizationCodeResponse {
    pub redirect_uri: String,

    pub stored_duration: Duration,

    pub username: String,

    pub scopes: String,

    pub authentication_time: DateTime<Local>,

    pub nonce: Option<String>,

    pub pkce_challenge: Option<CodeChallenge>,
}

pub struct ValidationRequest<'a> {
    pub client_id: &'a str,

    pub authorization_code: &'a str,

    pub validation_time: DateTime<Local>,
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    async fn get_authorization_code<'a>(&self, request: AuthorizationCodeRequest<'a>) -> String;

    async fn validate<'a>(
        &self,
        request: ValidationRequest<'a>,
    ) -> Option<AuthorizationCodeResponse>;
}

pub mod test_fixtures {
    use super::*;

    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::collections::HashMap;
    use std::iter::FromIterator;
    use std::sync::Arc;

    use crate::client::{Client, Error};
    use crate::oauth2::ClientType;
    use crate::password::Password;
    use crate::user::User;

    pub const UNKNOWN_USER: &str = "unknown_user";
    pub const USER: &str = "user1";

    struct TestUserStore {}

    #[async_trait]
    impl UserStore for TestUserStore {
        async fn get(&self, key: &str) -> Result<User, UserError> {
            match key {
                "user1" | "user2" | "user3" => Ok(User {
                    name: key.to_string(),
                    password: Password::Plain(key.to_string()),
                    allowed_scopes: Default::default(),
                    attributes: HashMap::new(),
                }),
                _ => Err(UserError::NotFound),
            }
        }
    }

    pub fn build_test_user_store() -> Arc<impl UserStore> {
        Arc::new(TestUserStore {})
    }

    pub const UNKNOWN_CLIENT_ID: &str = "unknown_client";
    pub const CONFIDENTIAL_CLIENT: &str = "client1";
    pub const PUBLIC_CLIENT: &str = "client2";

    struct TestClientStore {}

    #[async_trait]
    impl ClientStore for TestClientStore {
        async fn get(&self, key: &str) -> Result<Client, Error> {
            match key {
                "client1" => Ok(Client {
                    client_id: key.to_string(),
                    client_type: ClientType::Confidential {
                        password: Password::Plain("client1".to_string()),
                        public_key: None,
                    },
                    redirect_uris: vec!["http://localhost/client1".to_string()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_string()]),
                    attributes: HashMap::new(),
                }),
                "client2" => Ok(Client {
                    client_id: key.to_string(),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["http://localhost/client2".to_string()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_string()]),
                    attributes: HashMap::new(),
                }),
                _ => Err(Error::NotFound),
            }
        }
    }

    pub fn build_test_client_store() -> Arc<impl ClientStore> {
        Arc::new(TestClientStore {})
    }

    struct TestScopeStore {}

    impl ScopeStore for TestScopeStore {
        fn get(&self, key: &str) -> Option<Scope> {
            Some(Scope::new(key, key, key))
        }
        fn get_scope_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    pub fn build_test_scope_store() -> Arc<impl ScopeStore> {
        Arc::new(TestScopeStore {})
    }

    type AuthCodeStoreKey = (String, String);
    type AuthCodeStoreValue = (
        String,
        String,
        String,
        DateTime<Local>,
        DateTime<Local>,
        Option<String>,
        Option<CodeChallenge>,
    );

    struct TestAuthorizationCodeStore {
        store: RefCell<HashMap<AuthCodeStoreKey, AuthCodeStoreValue>>,
    }

    unsafe impl Sync for TestAuthorizationCodeStore {}
    unsafe impl Send for TestAuthorizationCodeStore {}

    #[async_trait]
    impl AuthorizationCodeStore for TestAuthorizationCodeStore {
        async fn get_authorization_code<'a>(
            &self,
            request: AuthorizationCodeRequest<'a>,
        ) -> String {
            self.store.borrow_mut().insert(
                (
                    request.client_id.to_string(),
                    request.insertion_time.to_rfc3339(),
                ),
                (
                    request.redirect_uri.to_string(),
                    request.user.to_string(),
                    request.scope.to_string(),
                    request.insertion_time,
                    request.authentication_time,
                    request.nonce,
                    request.pkce_challenge,
                ),
            );
            request.insertion_time.to_rfc3339()
        }

        async fn validate<'a>(
            &self,
            request: ValidationRequest<'a>,
        ) -> Option<AuthorizationCodeResponse> {
            let (
                redirect_uri,
                user,
                scope,
                insertion_time,
                authentication_time,
                nonce,
                pkce_challenge,
            ) = self.store.borrow_mut().remove(&(
                request.client_id.to_string(),
                request.authorization_code.to_string(),
            ))?;
            Some(AuthorizationCodeResponse {
                redirect_uri,
                stored_duration: request
                    .validation_time
                    .signed_duration_since(insertion_time),
                username: user,
                scopes: scope,
                authentication_time,
                nonce,
                pkce_challenge,
            })
        }
    }

    pub fn build_test_auth_code_store() -> Arc<impl AuthorizationCodeStore> {
        Arc::new(TestAuthorizationCodeStore {
            store: RefCell::new(HashMap::new()),
        })
    }
}
