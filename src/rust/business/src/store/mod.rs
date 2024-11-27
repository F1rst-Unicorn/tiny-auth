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

pub mod client_store;
pub mod memory;
pub mod user_store;

use crate::data::password::{Error as PasswordError, Password};
use crate::data::scope::Scope;
use crate::data::user::User;
use crate::pkce::CodeChallenge;
use async_trait::async_trait;
use chrono::DateTime;
use chrono::Duration;
use chrono::Local;
use futures_util::future::join_all;
use std::error::Error as StdError;
use std::sync::Arc;
use thiserror::Error;
use tracing::{instrument, Level};
use url::Url;

pub use client_store::ClientStore;
pub use user_store::UserStore;

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
