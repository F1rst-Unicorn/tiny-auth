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
use crate::data_assembler::{DataAssembler, Root};
use crate::error::SqliteError;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Local, Utc};
use itertools::Itertools;
use serde_json::Value;
use sqlx::error::ErrorKind;
use sqlx::sqlite::SqliteRow;
use sqlx::{query_file, SqlitePool};
use sqlx::{Column, Row, TypeInfo};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::iter::repeat;
use std::num::{NonZeroI64, NonZeroU32};
use std::sync::Arc;
use tiny_auth_business::client::Client;
use tiny_auth_business::client::Error as ClientError;
use tiny_auth_business::json_pointer::JsonPointer;
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::{
    Error as PasswordError, InPlacePasswordStore, Password, HASH_ITERATIONS,
};
use tiny_auth_business::pkce::{CodeChallenge, CodeChallengeMethod};
use tiny_auth_business::scope::{Destination, Mapping, Scope, Type};
use tiny_auth_business::store::memory::generate_random_string;
use tiny_auth_business::store::{
    AuthCodeError, AuthCodeValidationError, AuthorizationCodeRequest, AuthorizationCodeResponse,
    AuthorizationCodeStore, ClientStore, PasswordStore, ScopeStore, ScopeStoreError, UserStore,
    ValidationRequest,
};
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;
use tracing::{debug, error, span, Level};
use tracing::{instrument, warn};

pub struct SqliteStore {
    pub(crate) name: String,
    pub(crate) read_pool: SqlitePool,
    pub(crate) write_pool: SqlitePool,
    pub(crate) in_place_password_store: Arc<InPlacePasswordStore>,
    pub(crate) user_data_assembler: DataAssembler,
    pub(crate) client_data_assembler: DataAssembler,
}

#[macro_export]
macro_rules! chunked_query {
    ($query:literal, $keys:expr, $index_by:ident, $id_to_collect:ident, $transaction:ident) => {{
        let mut objects: BTreeMap<i64, Vec<_>> = BTreeMap::default();
        let mut ids = BTreeSet::default();
        if $keys.len() != 0 {
            let block_size = 8;
            let chunks: Vec<Vec<_>> = $keys
                .iter()
                .chain(repeat(
                    $keys.last().expect("validate there is at least one key"),
                ))
                .take($keys.len().next_multiple_of(block_size))
                .map(Clone::clone)
                .chunks(block_size)
                .into_iter()
                .map(|v| v.collect::<Vec<_>>())
                .collect();
            for chunk in &chunks {
                query_file!(
                    $query, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                    chunk[7],
                )
                .fetch_all(&mut *$transaction)
                .await
                .map_err(wrap_err)?
                .into_iter()
                .for_each(|v| {
                    ids.insert(v.$id_to_collect);
                    if let Some(container) = objects.get_mut(&v.$index_by) {
                        container.push(v);
                    } else {
                        objects.insert(v.$index_by, vec![v]);
                    }
                });
            }
        }
        (objects, ids)
    }};
}

#[async_trait]
impl AuthorizationCodeStore for SqliteStore {
    #[instrument(skip_all, fields(store = self.name), ret(level = Level::DEBUG))]
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
    #[instrument(skip_all, fields(store = self.name))]
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

        let user_id = user_record.try_get("id").map_err(wrap_err)?;
        let allowed_scopes = Self::load_allowed_user_scopes(&mut transaction, user_id).await?;

        let mut user = User {
            name: String::from(username),
            password: self
                .load_password(
                    user_record.try_get("password").map_err(wrap_err)?,
                    &mut transaction,
                )
                .await
                .map_err(wrap_err)?,
            allowed_scopes,
            attributes: Self::map_attributes(user_record, &["id"]),
        };
        let mut user_as_value = user.clone();
        user_as_value
            .attributes
            .insert(String::from("id"), user_id.into());
        let user_as_value = serde_json::to_value(user_as_value).unwrap();
        user.attributes = self
            .user_data_assembler
            .load(user_as_value, user_id, &mut transaction, Root::User)
            .await
            .map_err(wrap_err)?;
        transaction.commit().await.map_err(wrap_err)?;

        Ok(user)
    }
}

#[async_trait]
impl ClientStore for SqliteStore {
    #[instrument(skip_all, fields(store = self.name))]
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

        let mut client = Client {
            client_id: key.to_string(),
            client_type: self
                .map_client_type(&client_record, &mut transaction)
                .await?,
            redirect_uris,
            allowed_scopes: BTreeSet::from_iter(allowed_scopes),
            attributes: Self::map_attributes(client_record, &["id"]),
        };
        let mut client_as_value = client.clone();
        client_as_value
            .attributes
            .insert(String::from("id"), client_id.into());
        let client_as_value = serde_json::to_value(client_as_value).unwrap();
        client.attributes = self
            .client_data_assembler
            .load(client_as_value, client_id, &mut transaction, Root::Client)
            .await
            .map_err(wrap_err)?;

        transaction.commit().await.map_err(wrap_err)?;
        Ok(client)
    }
}

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
}

#[async_trait]
impl ScopeStore for SqliteStore {
    #[instrument(skip_all, fields(store = self.name, scopes = keys.join(" ")))]
    async fn get_all(&self, keys: &[String]) -> Result<Vec<Scope>, ScopeStoreError> {
        let mut conn = self.read_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        let (scopes, scope_ids) = chunked_query!(
            "queries/get-scopes.sql",
            keys.iter().cloned().collect::<BTreeSet<String>>(),
            id,
            id,
            transaction
        );
        let (mut scope_mappings, scope_mapping_ids) = chunked_query!(
            "queries/get-scope-mappings.sql",
            scope_ids,
            scope,
            mapping_id,
            transaction
        );
        drop(scope_ids);
        let (client_mappings_by_mapping, _) = chunked_query!(
            "queries/get-scope-mappings-client-attribute.sql",
            scope_mapping_ids,
            id,
            id,
            transaction
        );
        let (plain_mappings_by_mapping, _) = chunked_query!(
            "queries/get-scope-mappings-plain.sql",
            scope_mapping_ids,
            id,
            id,
            transaction
        );
        let (template_mappings_by_mapping, _) = chunked_query!(
            "queries/get-scope-mappings-template.sql",
            scope_mapping_ids,
            id,
            id,
            transaction
        );
        let (user_mappings_by_mapping, _) = chunked_query!(
            "queries/get-scope-mappings-user-attribute.sql",
            scope_mapping_ids,
            id,
            id,
            transaction
        );
        drop(scope_mapping_ids);

        transaction.commit().await.map_err(wrap_err)?;

        Ok(scopes
            .into_iter()
            .filter_map(|(_, mut v)| v.pop())
            .map(|scope| {
                let _scope_span = span!(Level::INFO, "", scope = %scope.name).entered();
                let mappings = scope_mappings
                    .remove(&scope.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mapping| {
                        let _mapping_span = span!(Level::INFO, "", mapping = %mapping.id).entered();
                        let mut destinations = BTreeSet::new();
                        if mapping.destination_access_token == 1 {
                            destinations.insert(Destination::AccessToken);
                        }
                        if mapping.destination_userinfo == 1 {
                            destinations.insert(Destination::UserInfo);
                        }
                        if mapping.destination_id_token == 1 {
                            destinations.insert(Destination::IdToken);
                        }

                        let (structure, mapping_type) = match mapping.r#type.as_str() {
                            "plain" => {
                                plain_mappings_by_mapping.get(&mapping.mapping_id)
                                    .and_then(|v| v.first())
                                    .and_then(|plain_mapping| {
                                        match JsonPointer::try_from(plain_mapping.structure.as_str()) {
                                            Err(e) => {
                                                warn!(%e, id = plain_mapping.id, "failed to read plain mapping structure");
                                                None
                                            }
                                            Ok(pointer) => {
                                                let mut value = pointer.construct_json();
                                                *value.pointer_mut(String::from(pointer).as_str()).unwrap() =
                                                    Self::map_value_by_type(plain_mapping.value.as_str(), plain_mapping.r#type.as_str());
                                                Some((value, Type::Plain))
                                            }
                                        }
                                    })
                                    .unwrap_or((Value::Null, Type::Plain))
                            }
                            "template" => {
                                template_mappings_by_mapping.get(&mapping.mapping_id)
                                    .and_then(|v| v.first())
                                    .and_then(|template_mapping| {
                                        match JsonPointer::try_from(template_mapping.structure.as_str()) {
                                            Err(e) => {
                                                warn!(%e, id = template_mapping.id, "failed to read template mapping structure");
                                                None
                                            }
                                            Ok(pointer) => {
                                                let mut value = pointer.construct_json();
                                                *value.pointer_mut(String::from(pointer).as_str()).unwrap() = template_mapping.template.clone().into();
                                                Some((value, Type::Template))
                                            }
                                        }
                                    })
                                    .unwrap_or((Value::Null, Type::Plain))
                            }
                            "user_attribute" => {
                                user_mappings_by_mapping.get(&mapping.mapping_id)
                                    .and_then(|v| v.first())
                                    .and_then(|user_mapping| {
                                        match JsonPointer::try_from(user_mapping.structure.as_str()) {
                                            Err(e) => {
                                                warn!(%e, id = user_mapping.id, "failed to read user mapping structure");
                                                None
                                            }
                                            Ok(structure) => {
                                                match JsonPointer::try_from(user_mapping.user_attribute.as_str()) {
                                                    Err(e) => {
                                                        warn!(%e, id = user_mapping.id, "failed to read user mapping attribute");
                                                        None
                                                    }
                                                    Ok(user_attribute) => {
                                                        Some((structure.construct_json(), Type::UserAttribute(user_attribute.construct_json())))
                                                    }
                                                }
                                            }
                                        }
                                    })
                                    .unwrap_or((Value::Null, Type::Plain))
                            }
                            "client_attribute" => {
                                client_mappings_by_mapping.get(&mapping.mapping_id)
                                    .and_then(|v| v.first())
                                    .and_then(|client_mapping| {
                                        match JsonPointer::try_from(client_mapping.structure.as_str()) {
                                            Err(e) => {
                                                warn!(%e, id = client_mapping.id, "failed to read client mapping structure");
                                                None
                                            }
                                            Ok(client_attribute) => {
                                                match JsonPointer::try_from(client_mapping.client_attribute.as_str()) {
                                                    Err(e) => {
                                                        warn!(%e, id = client_mapping.id, "failed to read client mapping attribute");
                                                        None
                                                    }
                                                    Ok(single_structure) => {
                                                        Some((single_structure.construct_json(), Type::ClientAttribute(client_attribute.construct_json())))
                                                    }
                                                }
                                            }
                                        }
                                    })
                                    .unwrap_or((Value::Null, Type::Plain))
                            }
                            _ => {
                                error!(r#type = %mapping.r#type,
                                    "Unknown mapping type. Don't drop DB constraints!");
                                (Value::Null, Type::Plain)
                            }
                        };
                        Mapping::new(structure, mapping_type, mapping.optional == 1, destinations)
                    })
                    .collect();

                Scope::from_attributes(
                    scope.name.as_str(),
                    scope.pretty_name.as_str(),
                    scope.description.as_str(),
                    mappings,
                )
            })
            .collect())
    }

    #[instrument(skip_all, fields(store = self.name))]
    async fn get_scope_names(&self) -> Result<Vec<String>, ScopeStoreError> {
        let mut conn = self.read_pool.acquire().await.map_err(wrap_err)?;
        let mut transaction = conn.begin_immediate().await.map_err(wrap_err)?;

        let names = sqlx::query_file_scalar!("queries/get-scope-names.sql")
            .fetch_all(&mut *transaction)
            .await
            .map_err(wrap_err)?;

        transaction.commit().await.map_err(wrap_err)?;
        Ok(names)
    }
}

impl SqliteStore {
    pub(crate) fn map_attributes(
        record: SqliteRow,
        ignored_columns: &[&str],
    ) -> HashMap<String, Value> {
        let mut attributes: HashMap<String, Value> = Default::default();
        for column in record.columns() {
            if ignored_columns.contains(&column.name()) {
                continue;
            }
            let value = match column.type_info().name().to_lowercase().as_str() {
                "int" | "integer" => record.get::<i32, _>(column.ordinal()).into(),
                "real" => record.get::<f64, _>(column.ordinal()).into(),
                "text" => record.get::<String, _>(column.ordinal()).into(),
                "blob" => record.get::<&[u8], _>(column.ordinal()).into(),
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
    ) -> Result<Vec<String>, ClientError> {
        let allowed_scopes: Vec<String> =
            sqlx::query_file_scalar!("queries/get-client-scopes.sql", client_id)
                .fetch_all(&mut **transaction)
                .await
                .map_err(wrap_err)?;
        Ok(allowed_scopes)
    }

    async fn map_client_type(
        &self,
        client_record: &SqliteRow,
        transaction: &mut Transaction<'_>,
    ) -> Result<ClientType, ClientError> {
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
                    password: self
                        .load_password(
                            client_record.try_get("password").map_err(wrap_err)?,
                            transaction,
                        )
                        .await
                        .map_err(wrap_err)?,
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
    ) -> Result<Vec<String>, ClientError> {
        let redirect_uris =
            sqlx::query_file_scalar!("queries/get-client-redirect-uris.sql", client_id)
                .fetch_all(&mut **transaction)
                .await
                .map_err(wrap_err)?;
        Ok(redirect_uris)
    }

    async fn load_password(
        &self,
        id: i32,
        transaction: &mut Transaction<'_>,
    ) -> Result<Password, SqliteError> {
        let password = query_file!("queries/get-password.sql", id)
            .fetch_one(&mut **transaction)
            .await?;
        match password.algorithm.as_str() {
            "pbkdf2hmacsha256" => Ok(Password::Sqlite {
                name: self.name.clone(),
                id,
            }),
            "ldap" => {
                if let Some(record) =
                    query_file!("queries/get-password-ldap.sql", password.password_id)
                        .fetch_optional(&mut **transaction)
                        .await?
                {
                    Ok(Password::Ldap {
                        name: record.store_name,
                    })
                } else {
                    error!("password not found");
                    Err(SqliteError::BackendError)
                }
            }
            algorithm => {
                error!(%algorithm, "unknown password algorithm. Don't drop DB constraints!");
                Err(SqliteError::BackendError)
            }
        }
    }

    fn map_value_by_type(value: &str, value_type: &str) -> Value {
        match value_type {
            "number" => match value.parse::<f64>() {
                Err(e) => {
                    warn!(%e, %value, "value is no number");
                    Value::Null
                }
                Ok(v) => v.into(),
            },
            "boolean" => match value.parse::<bool>() {
                Err(e) => {
                    warn!(%e, %value, "value is no boolean");
                    Value::Null
                }
                Ok(v) => v.into(),
            },
            "null" => Value::Null,
            "string" => value.into(),
            _ => {
                error!(r#type = %value_type,
                    "Unknown plain mapping type. Don't drop DB constraints!");
                Value::Null
            }
        }
    }
}
