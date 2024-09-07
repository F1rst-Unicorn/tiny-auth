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
use chrono::{DateTime, Duration, Local, Utc};
use serde_json::Value;
use sqlx::error::ErrorKind;
use sqlx::sqlite::SqliteRow;
use sqlx::SqlitePool;
use sqlx::{Column, Row, TypeInfo};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tiny_auth_business::client::Error as ClientError;
use tiny_auth_business::client::{Client, Error};
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::Password;
use tiny_auth_business::pkce::{CodeChallenge, CodeChallengeMethod};
use tiny_auth_business::store::memory::generate_random_string;
use tiny_auth_business::store::{
    AuthCodeError, AuthCodeValidationError, AuthorizationCodeRequest, AuthorizationCodeResponse,
    AuthorizationCodeStore, ClientStore, UserStore, ValidationRequest,
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

            match sqlx::query!(
                r#"
                insert into authorization_code (
                    client,
                    user,
                    redirect_uri,
                    scope,
                    code,
                    insertion_time,
                    authentication_time,
                    nonce,
                    pkce_challenge,
                    pkce_challenge_method)
                select
                    client.id,
                    user.id,
                    redirect_uri.id,
                    $4,
                    $5,
                    $8,
                    $6,
                    $7,
                    $9,
                    $10
                from client, user, redirect_uri
                where client.client_id = $1
                and user.name = $2
                and redirect_uri.client = client.id
                and redirect_uri.redirect_uri = $3
            "#,
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

        let Some(record) = sqlx::query!(
            r#"
                select
                    c.id,
                    redirect_uri.redirect_uri,
                    c.insertion_time,
                    user.name,
                    c.scope,
                    c.authentication_time,
                    c.nonce,
                    c.pkce_challenge,
                    c.pkce_challenge_method
                from authorization_code c
                join user on user.id = c.user
                join redirect_uri on redirect_uri.id = c.redirect_uri
                where c.code = $1
                and c.client = (
                    select client.id
                    from client
                    where client.client_id = $2
                )
            "#,
            request.authorization_code,
            request.client_id,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(wrap_err)?
        else {
            return Err(AuthCodeValidationError::NotFound);
        };

        sqlx::query!(
            r#"
            delete from authorization_code
            where id = $1
        "#,
            record.id
        )
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

        if let Err(e) = sqlx::query!(
            r#"
            delete from authorization_code
            where insertion_time < $1
        "#,
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

        let user_record = sqlx::query("select * from user where name = $1")
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

        let client_record = sqlx::query("select * from client where client_id = $1")
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
        let allowed_scopes_records = sqlx::query!(
            r#"
                select
                    client.client_id as client,
                    scope.name as scope
                from user_allowed_scopes uas
                join client on uas.client = client.id
                join scope on uas.scope = scope.id
                where user = $1
            "#,
            user_id
        )
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
        let allowed_scopes: Vec<String> = sqlx::query_scalar!(
            r#"
            select scope.name
            from client_allowed_scopes
            join scope on scope.id = client_allowed_scopes.scope
            where client_allowed_scopes.client = $1
        "#,
            client_id
        )
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
        let redirect_uris = sqlx::query_scalar!(
            r#"
            select redirect_uri.redirect_uri
            from redirect_uri
            where redirect_uri.client = $1
        "#,
            client_id
        )
        .fetch_all(&mut **transaction)
        .await
        .map_err(wrap_err)?;
        Ok(redirect_uris)
    }
}
