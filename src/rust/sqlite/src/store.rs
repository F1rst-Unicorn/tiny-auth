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
use crate::begin_immediate::{SqliteConnectionExt, Transaction};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Local, Utc};
use serde_json::Value;
use sqlx::error::ErrorKind;
use sqlx::sqlite::SqliteRow;
use sqlx::SqlitePool;
use sqlx::{Column, Row, TypeInfo};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::{NonZeroI64, NonZeroU32};
use std::sync::Arc;
use tiny_auth_business::client::Error as ClientError;
use tiny_auth_business::client::{Client, Error};
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::{
    Error as PasswordError, InPlacePasswordStore, Password, HASH_ITERATIONS,
};
use tiny_auth_business::pkce::{CodeChallenge, CodeChallengeMethod};
use tiny_auth_business::store::memory::generate_random_string;
use tiny_auth_business::store::{
    AuthCodeError, AuthCodeValidationError, AuthorizationCodeRequest, AuthorizationCodeResponse,
    AuthorizationCodeStore, ClientStore, PasswordStore, UserStore, ValidationRequest,
};
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;
use tracing::{debug, error, Level};
use tracing::{instrument, warn};

pub struct SqliteStore {
    pub(crate) name: String,
    pub(crate) read_pool: SqlitePool,
    pub(crate) write_pool: SqlitePool,
    pub(crate) in_place_password_store: Arc<InPlacePasswordStore>,
}

#[async_trait]
impl AuthorizationCodeStore for SqliteStore {
    #[instrument(skip_all, ret(level = Level::DEBUG))]
    async fn get_authorization_code<'a>(
        &self,
        request: AuthorizationCodeRequest<'a>,
    ) -> Result<String, AuthCodeError> {
        let mut conn = self.write_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        let encoded_auth_time = request.authentication_time.with_timezone(&Utc).to_rfc3339();
        let encoded_insertion_time = request.insertion_time.with_timezone(&Utc).to_rfc3339();
        let nonce = request.nonce.unwrap_or_default();
        let pkce_challenge = request
            .pkce_challenge
            .as_ref()
            .map(CodeChallenge::code_challenge);
        let pkce_challenge_method = request
            .pkce_challenge
            .as_ref()
            .map(CodeChallenge::code_challenge_method)
            .map(|v| format!("{}", v));

        let (result, auth_code) = loop {
            let auth_code = generate_random_string(32);

            match sqlx::query_file!(
                "queries/insert-authorization-code.sql",
                request.client_id,
                request.user,
                request.redirect_uri,
                request.scope,
                auth_code,
                encoded_auth_time,
                nonce,
                encoded_insertion_time,
                pkce_challenge,
                pkce_challenge_method,
            )
            .execute(&mut *transaction)
            .await
            {
                Ok(v) => break (v, auth_code),
                Err(sqlx::Error::Database(e)) => {
                    if e.kind() == ErrorKind::UniqueViolation
                        && e.message()
                            .contains("authorization_code.code, authorization_code.client")
                    {
                        continue;
                    } else {
                        return Err(AuthCodeError::BackendErrorWithContext(wrap_err(e)));
                    }
                }
                Err(e) => return Err(AuthCodeError::BackendErrorWithContext(wrap_err(e))),
            };
        };

        if result.rows_affected() != 1 {
            warn!(
                rows_affected = result.rows_affected(),
                "failed to store authorization code"
            );
        }

        transaction.commit().await.map_err(wrap_err)?;
        Ok(auth_code)
    }

    async fn validate<'a>(
        &self,
        request: ValidationRequest<'a>,
    ) -> Result<AuthorizationCodeResponse, AuthCodeValidationError> {
        let mut conn = self.write_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        let Some(record) = sqlx::query_file!(
            "queries/get-authorization-code.sql",
            request.authorization_code,
            request.client_id,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(wrap_err)?
        else {
            return Err(AuthCodeValidationError::NotFound);
        };

        sqlx::query_file!("queries/delete-authorization-code.sql", record.id)
            .execute(&mut *transaction)
            .await
            .map_err(wrap_err)?;

        let Ok(insertion_time) =
            DateTime::parse_from_rfc3339(&record.insertion_time).map(|v| v.with_timezone(&Local))
        else {
            debug!(value = record.insertion_time, "invalid raw insertion time");
            return Err(AuthCodeValidationError::NotFound);
        };

        let Ok(authentication_time) = DateTime::parse_from_rfc3339(&record.authentication_time)
            .map(|v| v.with_timezone(&Local))
        else {
            debug!(
                value = record.authentication_time,
                "invalid raw authentication time"
            );
            return Err(AuthCodeValidationError::NotFound);
        };

        let pkce_challenge = record
            .pkce_challenge
            .zip(
                record
                    .pkce_challenge_method
                    .as_ref()
                    .map(CodeChallengeMethod::try_from)
                    .and_then(Result::ok),
            )
            .map(|(u, v)| unsafe { CodeChallenge::from_parts(u, v) });

        transaction.commit().await.map_err(wrap_err)?;
        Ok(AuthorizationCodeResponse {
            redirect_uri: record.redirect_uri,
            stored_duration: request.validation_time - (insertion_time),
            username: record.name,
            scopes: record.scope,
            authentication_time,
            nonce: record.nonce,
            pkce_challenge,
        })
    }

    async fn clear_expired_codes(&self, now: DateTime<Local>, validity: Duration) {
        let earliest_valid_insertion_time = (now - validity).with_timezone(&Utc).to_rfc3339();

        let mut conn = match self.write_pool.acquire().await {
            Ok(v) => v,
            Err(e) => {
                error!(%e, "failed to open connection to clear expired authorization codes");
                return;
            }
        };
        let mut transaction = match conn.begin_immediate().await {
            Ok(v) => v,
            Err(e) => {
                error!(%e, "failed to open transaction to clear expired authorization codes");
                return;
            }
        };

        if let Err(e) = sqlx::query_file!(
            "queries/delete-expired-authorization-codes.sql",
            earliest_valid_insertion_time
        )
        .execute(&mut *transaction)
        .await
        {
            error!(%e, "failed to clear expired authorization codes");
        }

        if let Err(e) = transaction.commit().await {
            error!(%e, "failed to commit to clear expired authorization codes");
        }
    }
}

#[async_trait]
impl UserStore for SqliteStore {
    async fn get(&self, username: &str) -> Result<User, UserError> {
        let mut conn = self.read_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        // Assume unknown columns at runtime, so don't use sqlx static query checking
        let user_record = sqlx::query("select * from tiny_auth_user where name = $1")
            .bind(username)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(wrap_err)?
            .ok_or(UserError::NotFound)?;

        let allowed_scopes = Self::load_allowed_user_scopes(
            &mut transaction,
            user_record.try_get("id").map_err(wrap_err)?,
        )
        .await?;

        transaction.commit().await.map_err(wrap_err)?;
        Ok(User {
            name: String::from(username),
            password: Password::Sqlite {
                name: self.name.clone(),
                id: user_record.try_get("password").map_err(wrap_err)?,
            },
            allowed_scopes,
            attributes: Self::map_attributes(user_record),
        })
    }
}

#[async_trait]
impl ClientStore for SqliteStore {
    async fn get(&self, key: &str) -> Result<Client, ClientError> {
        let mut conn = self.read_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        // Assume unknown columns at runtime, so don't use sqlx static query checking
        let client_record = sqlx::query("select * from tiny_auth_client where client_id = $1")
            .bind(key)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(wrap_err)?
            .ok_or(ClientError::NotFound)?;

        let client_id: i32 = client_record.try_get("id").map_err(wrap_err)?;
        let redirect_uris = Self::load_redirect_uris(&mut transaction, client_id).await?;
        let allowed_scopes = Self::load_allowed_client_scopes(&mut transaction, client_id).await?;

        transaction.commit().await.map_err(wrap_err)?;
        Ok(Client {
            client_id: key.to_string(),
            client_type: self.map_client_type(&client_record)?,
            redirect_uris,
            allowed_scopes: BTreeSet::from_iter(allowed_scopes),
            attributes: Self::map_attributes(client_record),
        })
    }
}

#[async_trait]
impl PasswordStore for SqliteStore {
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

        let algorithm = sqlx::query_file_scalar!("queries/get-password.sql", id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(wrap_err)?;

        if let "pbkf2hmacsha256" = algorithm.as_str() {
            if let Some(record) = sqlx::query_file!("queries/get-password-pbkdf2hmacsha256.sql", id)
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
        } else {
            error!("password not found");
            Err(PasswordError::BackendError)
        }
    }
}

impl SqliteStore {
    fn map_attributes(user_record: SqliteRow) -> HashMap<String, Value> {
        let mut attributes: HashMap<String, Value> = Default::default();
        for column in user_record.columns() {
            if column.name() == "id" {
                continue;
            }
            let value = match column.type_info().name().to_lowercase().as_str() {
                "int" | "integer" => user_record.get::<i32, _>(column.ordinal()).into(),
                "real" => user_record.get::<f64, _>(column.ordinal()).into(),
                "text" => user_record.get::<String, _>(column.ordinal()).into(),
                "blob" => user_record.get::<&[u8], _>(column.ordinal()).into(),
                v => {
                    warn!(column_type = %v, column_name = %column.name(), "unsupported");
                    continue;
                }
            };
            attributes.insert(column.name().to_string(), value);
        }
        attributes
    }

    async fn load_allowed_user_scopes(
        transaction: &mut Transaction<'_>,
        user_id: i32,
    ) -> Result<BTreeMap<String, BTreeSet<String>>, UserError> {
        let allowed_scopes_records = sqlx::query_file!("queries/get-user-scopes.sql", user_id)
            .fetch_all(&mut **transaction)
            .await
            .map_err(wrap_err)?;

        let mut allowed_scopes: BTreeMap<String, BTreeSet<String>> = Default::default();
        for record in allowed_scopes_records {
            let record_scope = record.scope.clone();
            allowed_scopes
                .entry(record.client)
                .and_modify(|v| {
                    v.insert(record_scope);
                })
                .or_insert_with(|| {
                    let mut scopes: BTreeSet<String> = Default::default();
                    scopes.insert(record.scope);
                    scopes
                });
        }
        Ok(allowed_scopes)
    }

    async fn load_allowed_client_scopes(
        transaction: &mut Transaction<'_>,
        client_id: i32,
    ) -> Result<Vec<String>, Error> {
        let allowed_scopes: Vec<String> =
            sqlx::query_file_scalar!("queries/get-client-scopes.sql", client_id)
                .fetch_all(&mut **transaction)
                .await
                .map_err(wrap_err)?;
        Ok(allowed_scopes)
    }

    fn map_client_type(&self, client_record: &SqliteRow) -> Result<ClientType, ClientError> {
        let client_type = match client_record
            .try_get::<&str, _>("client_type")
            .map_err(wrap_err)?
        {
            "public" => ClientType::Public,
            "confidential" => {
                let public_key = client_record
                    .try_get::<Option<&str>, _>("public_key")
                    .map_err(wrap_err)?
                    .map(String::from);
                ClientType::Confidential {
                    password: Password::Sqlite {
                        name: self.name.clone(),
                        id: client_record.try_get("password").map_err(wrap_err)?,
                    },
                    public_key,
                }
            }
            v => {
                warn!(client_type = %v, "unknown value");
                return Err(ClientError::NotFound);
            }
        };
        Ok(client_type)
    }

    async fn load_redirect_uris(
        transaction: &mut Transaction<'_>,
        client_id: i32,
    ) -> Result<Vec<String>, Error> {
        let redirect_uris =
            sqlx::query_file_scalar!("queries/get-client-redirect-uris.sql", client_id)
                .fetch_all(&mut **transaction)
                .await
                .map_err(wrap_err)?;
        Ok(redirect_uris)
    }
}
