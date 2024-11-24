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
use std::error::Error as StdError;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, Level};
use url::Url;

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

#[derive(Error, Debug)]
pub enum PasswordConstructionError {
    #[error("unchanged")]
    PasswordUnchanged(Password, PasswordUnchangedReason),
    #[error("Unknown password store '{0}'")]
    UnmatchedBackendName(String),
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[derive(Debug)]
pub enum PasswordUnchangedReason {
    Managed,
    Insecure,
}

#[async_trait]
pub trait PasswordStore: Send + Sync {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, PasswordError>;

    async fn construct_password(
        &self,
        user: User,
        password: &str,
    ) -> Result<Password, PasswordConstructionError>;
}

#[derive(Error, Debug, Clone)]
pub enum ScopeStoreError {
    #[error("not found")]
    NotFound,
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[async_trait]
pub trait ScopeStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Scope, ScopeStoreError> {
        self.get_all(&[key.to_owned()])
            .await
            .and_then(|mut v| v.pop().ok_or(ScopeStoreError::NotFound))
    }

    async fn get_all(&self, keys: &[String]) -> Result<Vec<Scope>, ScopeStoreError>;

    async fn get_scope_names(&self) -> Result<Vec<String>, ScopeStoreError>;
}

pub struct MergingScopeStore {
    stores: Vec<Arc<dyn ScopeStore>>,
}

impl From<Vec<Arc<dyn ScopeStore>>> for MergingScopeStore {
    fn from(value: Vec<Arc<dyn ScopeStore>>) -> Self {
        Self { stores: value }
    }
}

#[async_trait]
impl ScopeStore for MergingScopeStore {
    #[instrument(level = Level::DEBUG, name = "get_scope", skip_all)]
    async fn get_all(&self, keys: &[String]) -> Result<Vec<Scope>, ScopeStoreError> {
        join_all(keys.iter().map(|key| async {
            join_all(self.stores.iter().map(|v| v.get(key.as_str())))
                .await
                .into_iter()
                .filter(|v| !matches!(v, Err(ScopeStoreError::NotFound)))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|v| {
                    v.into_iter()
                        .reduce(Scope::merge)
                        .ok_or(ScopeStoreError::NotFound)
                })
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
    }

    async fn get_scope_names(&self) -> Result<Vec<String>, ScopeStoreError> {
        join_all(self.stores.iter().map(|v| v.get_scope_names()))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, ScopeStoreError>>()
            .map(|v| v.into_iter().flatten().collect())
    }
}

/// Recommended lifetime is 10 minutes as of the [RFC](https://tools.ietf.org/html/rfc6749#section-4.1.2)
pub const AUTH_CODE_LIFE_TIME: i64 = 10;

#[derive(Clone)]
pub struct AuthorizationCodeRequest<'a> {
    pub client_id: &'a str,

    pub user: &'a str,

    pub redirect_uri: &'a Url,

    pub scope: &'a str,

    pub insertion_time: DateTime<Local>,

    pub authentication_time: DateTime<Local>,

    pub nonce: Option<String>,

    pub pkce_challenge: Option<CodeChallenge>,
}

#[derive(Debug)]
pub struct AuthorizationCodeResponse {
    pub redirect_uri: Url,

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

#[derive(Error, Debug, Clone)]
pub enum AuthCodeError {
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[derive(Error, Debug, Clone)]
pub enum AuthCodeValidationError {
    #[error("not found")]
    NotFound,
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    async fn get_authorization_code<'a>(
        &self,
        request: AuthorizationCodeRequest<'a>,
    ) -> Result<String, AuthCodeError>;

    async fn validate<'a>(
        &self,
        request: ValidationRequest<'a>,
    ) -> Result<AuthorizationCodeResponse, AuthCodeValidationError>;

    async fn clear_expired_codes(&self, now: DateTime<Local>, validity: Duration);
}

pub mod test_fixtures {
    use super::*;

    use crate::client::{Client, Error};
    use crate::oauth2::ClientType;
    use crate::password::Password;
    use crate::store::AuthCodeValidationError::NotFound;
    use crate::token::TokenValidator;
    use crate::user::User;
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::collections::HashMap;
    use std::iter::FromIterator;
    use std::sync::Arc;
    use url::Url;

    pub const UNKNOWN_USER: &str = "unknown_user";
    pub const USER: &str = "user1";

    struct TestUserStore {}

    #[async_trait]
    impl UserStore for TestUserStore {
        async fn get(&self, key: &str) -> Result<User, UserError> {
            match key {
                "user1" | "user2" | "user3" => Ok(User {
                    name: key.to_owned(),
                    password: Password::Plain(key.to_owned()),
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
    pub const TINY_AUTH_FRONTEND_CLIENT: &str = TokenValidator::TINY_AUTH_FRONTEND_CLIENT_ID;

    struct TestClientStore {}

    #[async_trait]
    impl ClientStore for TestClientStore {
        async fn get(&self, key: &str) -> Result<Client, Error> {
            match key {
                "client1" => Ok(Client {
                    client_id: key.to_owned(),
                    client_type: ClientType::Confidential {
                        password: Password::Plain("client1".to_owned()),
                        public_key: None,
                    },
                    #[allow(clippy::unwrap_used)] // test code
                    redirect_uris: vec![Url::parse("http://localhost/client1").unwrap()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_owned()]),
                    attributes: HashMap::new(),
                }),
                "client2" => Ok(Client {
                    client_id: key.to_owned(),
                    client_type: ClientType::Public,
                    #[allow(clippy::unwrap_used)] // test code
                    redirect_uris: vec![Url::parse("http://localhost/client2").unwrap()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_owned()]),
                    attributes: HashMap::new(),
                }),
                "tiny-auth-frontend" => Ok(Client {
                    client_id: key.to_owned(),
                    client_type: ClientType::Public,
                    #[allow(clippy::unwrap_used)] // test code
                    redirect_uris: vec![Url::parse("http://localhost/client2").unwrap()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_owned()]),
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

    #[async_trait]
    impl ScopeStore for TestScopeStore {
        async fn get_all(&self, keys: &[String]) -> Result<Vec<Scope>, ScopeStoreError> {
            Ok(keys
                .iter()
                .map(|v| Scope::new(v.as_str(), v.as_str(), v.as_str()))
                .collect())
        }
        async fn get_scope_names(&self) -> Result<Vec<String>, ScopeStoreError> {
            Ok(Vec::new())
        }
    }

    pub fn build_test_scope_store() -> Arc<impl ScopeStore> {
        Arc::new(TestScopeStore {})
    }

    type AuthCodeStoreKey = (String, String);
    type AuthCodeStoreValue = (
        Url,
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
        ) -> Result<String, AuthCodeError> {
            self.store.borrow_mut().insert(
                (
                    request.client_id.to_owned(),
                    request.insertion_time.to_rfc3339(),
                ),
                (
                    request.redirect_uri.to_owned(),
                    request.user.to_owned(),
                    request.scope.to_owned(),
                    request.insertion_time,
                    request.authentication_time,
                    request.nonce,
                    request.pkce_challenge,
                ),
            );
            Ok(request.insertion_time.to_rfc3339())
        }

        async fn validate<'a>(
            &self,
            request: ValidationRequest<'a>,
        ) -> Result<AuthorizationCodeResponse, AuthCodeValidationError> {
            let (
                redirect_uri,
                user,
                scope,
                insertion_time,
                authentication_time,
                nonce,
                pkce_challenge,
            ) = self
                .store
                .borrow_mut()
                .remove(&(
                    request.client_id.to_owned(),
                    request.authorization_code.to_owned(),
                ))
                .ok_or(NotFound)?;
            Ok(AuthorizationCodeResponse {
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

        async fn clear_expired_codes(&self, _: DateTime<Local>, _: Duration) {}
    }

    pub fn build_test_auth_code_store() -> Arc<impl AuthorizationCodeStore> {
        Arc::new(TestAuthorizationCodeStore {
            store: RefCell::new(HashMap::new()),
        })
    }
}