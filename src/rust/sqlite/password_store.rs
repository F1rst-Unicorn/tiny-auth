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
use crate::begin_immediate::SqliteConnectionExt;
use crate::store::SqliteStore;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sqlx::{query_file, query_file_scalar};
use std::num::{NonZeroI64, NonZeroU32};
use tiny_auth_business::password::{Error as PasswordError, Password, HASH_ITERATIONS};
use tiny_auth_business::store::PasswordConstructionError::BackendError;
use tiny_auth_business::store::{
    PasswordConstructionError, PasswordStore, PasswordUnchangedReason,
};
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;
use tracing::{error, info};
use tracing::{instrument, warn};

#[async_trait]
impl PasswordStore for SqliteStore {
    #[instrument(skip_all, fields(store = self.name))]
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, PasswordError> {
        let id = match stored_password {
            Password::Sqlite { name, id } => {
                if name != &self.name {
                    error!(
                        my_name = self.name,
                        password_name = name,
                        "password store dispatch bug"
                    );
                    return Err(PasswordError::BackendError);
                }
                id
            }
            _ => {
                error!("password store dispatch bug");
                return Err(PasswordError::BackendError);
            }
        };
        let mut conn = self.read_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        let password = query_file!("queries/get-password.sql", id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(wrap_err)?;

        match password.algorithm.as_str() {
            "pbkdf2hmacsha256" => {
                if let Some(record) = query_file!(
                    "queries/get-password-pbkdf2hmacsha256.sql",
                    password.password_id
                )
                .fetch_optional(&mut *transaction)
                .await
                .map_err(wrap_err)?
                {
                    let password = Password::Pbkdf2HmacSha256 {
                        credential: STANDARD.encode(record.credential),
                        iterations: NonZeroI64::try_from(record.iterations)
                            .and_then(NonZeroU32::try_from)
                            .unwrap_or(HASH_ITERATIONS),
                        salt: STANDARD.encode(record.salt),
                    };

                    transaction.commit().await.map_err(wrap_err)?;
                    self.in_place_password_store
                        .verify(username, &password, password_to_check)
                        .await
                } else {
                    error!("password not found");
                    Err(PasswordError::BackendError)
                }
            }
            algorithm => {
                error!(%algorithm, "unknown password algorithm. Don't drop DB constraints!");
                Err(PasswordError::BackendError)
            }
        }
    }

    #[instrument(skip_all, fields(store = self.name))]
    async fn construct_password(
        &self,
        user: User,
        password: &str,
    ) -> Result<Password, PasswordConstructionError> {
        let existing_password_id = match &user.password {
            Password::Pbkdf2HmacSha256 { .. } => {
                info!("password will be moved into the DB");
                None
            }
            Password::Plain(_) => {
                info!("password will be upgraded into an encrypted one");
                None
            }
            Password::Ldap { .. } => {
                warn!("LDAP passwords cannot be changed");
                return Err(PasswordConstructionError::PasswordUnchanged(
                    user.password,
                    PasswordUnchangedReason::Managed,
                ));
            }
            Password::Sqlite { name, id } => {
                if self.name.ne(name) {
                    error!(
                        my_name = self.name,
                        password_name = name,
                        "password store dispatch bug"
                    );
                    return Err(PasswordConstructionError::BackendError);
                }
                Some(id).cloned()
            }
        };

        let new_password = self
            .in_place_password_store
            .construct_password(user, password)
            .await?;

        match new_password {
            Password::Pbkdf2HmacSha256 {
                credential,
                iterations,
                salt,
            } => {
                let mut conn = self.write_pool.acquire().await.map_err(wrap_err)?;
                let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;
                let credential = STANDARD.decode(&credential).map_err(|_| {
                    error!(credential = %credential.clone(), "no valid base64 string");
                    BackendError
                })?;
                let salt = STANDARD.decode(&salt).map_err(|_| {
                    error!(%salt, "no valid base64 string");
                    BackendError
                })?;
                let id = if let Some(id) = existing_password_id {
                    query_file!(
                        "queries/update-password-pbkdf2hmacsha256.sql",
                        credential,
                        iterations,
                        salt,
                        id
                    )
                    .execute(&mut *transaction)
                    .await
                    .map_err(wrap_err)?;
                    id
                } else {
                    let specialisation_id = match query_file_scalar!(
                        "queries/insert-password-pbkdf2hmacsha256.sql",
                        credential,
                        iterations,
                        salt,
                    )
                    .fetch_one(&mut *transaction)
                    .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(%e, "failed to store password data");
                            return Err(BackendError);
                        }
                    };
                    match query_file_scalar!(
                        "queries/insert-password.sql",
                        "pbkdf2hmacsha256",
                        specialisation_id
                    )
                    .fetch_one(&mut *transaction)
                    .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(%e, "failed to store password");
                            return Err(BackendError);
                        }
                    }
                };
                transaction.commit().await.map_err(wrap_err)?;
                Ok(Password::Sqlite {
                    name: self.name.clone(),
                    id,
                })
            }
            v @ Password::Ldap { .. } | v @ Password::Sqlite { .. } => Err(
                PasswordConstructionError::PasswordUnchanged(v, PasswordUnchangedReason::Managed),
            ),
            Password::Plain(_) => {
                error!("plain text passwords are not stored in the DB");
                Err(PasswordConstructionError::PasswordUnchanged(
                    new_password,
                    PasswordUnchangedReason::Insecure,
                ))
            }
        }
    }
}
