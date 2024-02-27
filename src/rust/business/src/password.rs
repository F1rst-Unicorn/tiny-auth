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

use crate::store::PasswordStore;
use crate::user::User;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::error;
use rand::random;
use ring::digest;
use ring::pbkdf2;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::num::NonZeroU32;
use std::sync::Arc;
use thiserror::Error;

const HASH_ITERATIONS: u32 = 100_000;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Unknown password store '{0}'")]
    UnmatchedBackendName(String),
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Password {
    Pbkdf2HmacSha256 {
        credential: String,

        iterations: NonZeroU32,

        salt: String,
    },

    #[serde(alias = "plain")]
    Plain(String),

    #[serde(rename = "ldap")]
    Ldap { name: String },
}

impl Password {
    pub fn new(username: &str, password: &str, pepper: &str) -> Self {
        let salt = generate_salt(username);
        let mut salt_and_pepper = salt.clone();
        salt_and_pepper.extend(pepper.as_bytes());
        let mut credentials = [0u8; digest::SHA256_OUTPUT_LEN];
        let iterations = NonZeroU32::new(HASH_ITERATIONS).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            &salt_and_pepper,
            password.as_bytes(),
            &mut credentials,
        );
        Self::Pbkdf2HmacSha256 {
            credential: STANDARD.encode(credentials),
            iterations,
            salt: STANDARD.encode(salt),
        }
    }
}

pub struct DispatchingPasswordStore {
    named_stores: BTreeMap<String, Arc<dyn PasswordStore>>,
    in_place_store: Arc<InPlacePasswordStore>,
}

impl DispatchingPasswordStore {
    pub fn construct_password(&self, user: User, password: &str) -> Password {
        match user.password {
            ldap @ Password::Ldap { .. } => ldap,
            Password::Plain(_) | Password::Pbkdf2HmacSha256 { .. } => {
                self.in_place_store.construct_password(&user.name, password)
            }
        }
    }
}

#[async_trait]
impl PasswordStore for DispatchingPasswordStore {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error> {
        match stored_password {
            Password::Ldap { name } => {
                let store = self
                    .named_stores
                    .get(name)
                    .ok_or(Error::UnmatchedBackendName(name.clone()))?;
                store
                    .verify(username, stored_password, password_to_check)
                    .await
            }
            Password::Plain(_) | Password::Pbkdf2HmacSha256 { .. } => {
                self.in_place_store
                    .verify(username, stored_password, password_to_check)
                    .await
            }
        }
    }
}

pub struct InPlacePasswordStore {
    pepper: String,
}

impl InPlacePasswordStore {
    pub fn construct_password(&self, username: &str, password: &str) -> Password {
        Password::new(username, password, &self.pepper)
    }
}

#[async_trait]
impl PasswordStore for InPlacePasswordStore {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error> {
        match stored_password {
            Password::Plain(stored_password) => Ok(stored_password == password_to_check),
            Password::Pbkdf2HmacSha256 {
                credential,
                iterations,
                salt,
            } => {
                let credential = match STANDARD.decode(credential) {
                    Err(e) => {
                        error!("Failed to decode credential of user '{}': {}", username, e);
                        return Err(Error::BackendError);
                    }
                    Ok(v) => v,
                };

                let salt = match STANDARD.decode(salt) {
                    Err(e) => {
                        error!("Failed to decode salt of user '{}': {}", username, e);
                        return Err(Error::BackendError);
                    }
                    Ok(v) => v,
                };

                let mut salt_and_pepper = salt;
                salt_and_pepper.extend(self.pepper.as_bytes());

                Ok(pbkdf2::verify(
                    pbkdf2::PBKDF2_HMAC_SHA256,
                    *iterations,
                    &salt_and_pepper,
                    password_to_check.as_bytes(),
                    &credential,
                )
                .is_ok())
            }
            Password::Ldap { name } => {
                error!(
                    "Password store dispatch bug. Password names {} but this is the in-place store",
                    name
                );
                Err(Error::BackendError)
            }
        }
    }
}

fn generate_salt(username: &str) -> Vec<u8> {
    const RANDOM_SALT_LENGTH: usize = 32;
    let random_salt: [u8; RANDOM_SALT_LENGTH] = random();
    let mut result = Vec::with_capacity(RANDOM_SALT_LENGTH + username.len());
    result.extend(random_salt);
    result.extend(username.as_bytes());
    result
}

pub mod inject {
    use super::*;

    pub fn in_place_password_store(pepper: &str) -> InPlacePasswordStore {
        InPlacePasswordStore {
            pepper: pepper.to_string(),
        }
    }

    pub fn dispatching_password_store(
        named_stores: BTreeMap<String, Arc<dyn PasswordStore>>,
        in_place_store: Arc<InPlacePasswordStore>,
    ) -> DispatchingPasswordStore {
        DispatchingPasswordStore {
            named_stores,
            in_place_store,
        }
    }
}

pub mod test_fixtures {
    use super::*;

    pub fn in_place_password_store() -> InPlacePasswordStore {
        InPlacePasswordStore {
            pepper: "pepper".to_string(),
        }
    }

    pub fn dispatching_password_store() -> DispatchingPasswordStore {
        DispatchingPasswordStore {
            named_stores: Default::default(),
            in_place_store: Arc::new(in_place_password_store()),
        }
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use test_log::test;

    #[test(tokio::test)]
    pub async fn passwords_can_be_verified() {
        let uut = InPlacePasswordStore {
            pepper: "pepper".to_string(),
        };
        let password = "password";
        let pw = Password::new("username", password, "pepper");

        assert!(uut.verify("username", &pw, password).await.unwrap())
    }
}
