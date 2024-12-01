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

use crate::data::password::{Error as PasswordError, Password};
use crate::data::user::User;
use async_trait::async_trait;
use std::error::Error as StdError;
use std::sync::Arc;
use thiserror::Error;

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
