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
use crate::data_assembler::Root;
use crate::store::SqliteStore;
use async_trait::async_trait;
use sqlx::query_file_scalar;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use std::collections::BTreeSet;
use tiny_auth_business::client::Client;
use tiny_auth_business::client::Error as ClientError;
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::util::wrap_err;
use tracing::{instrument, warn};

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
        let redirect_uris = load_redirect_uris(&mut transaction, client_id).await?;
        let allowed_scopes = load_allowed_client_scopes(&mut transaction, client_id).await?;

        let mut client = Client {
            client_id: key.to_owned(),
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
        let client_as_value = serde_json::to_value(client_as_value).map_err(wrap_err)?;
        client.attributes = self
            .client_data_assembler
            .load(client_as_value, client_id, &mut transaction, Root::Client)
            .await
            .map_err(wrap_err)?;

        transaction.commit().await.map_err(wrap_err)?;
        Ok(client)
    }
}

impl SqliteStore {
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

async fn load_redirect_uris(
    transaction: &mut Transaction<'_>,
    client_id: i32,
) -> Result<Vec<String>, ClientError> {
    let redirect_uris = query_file_scalar!("queries/get-client-redirect-uris.sql", client_id)
        .fetch_all(&mut **transaction)
        .await
        .map_err(wrap_err)?;
    Ok(redirect_uris)
}
