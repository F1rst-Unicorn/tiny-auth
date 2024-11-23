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
use crate::begin_immediate::Transaction;
use crate::data_assembler::DataAssembler;
use crate::error::SqliteError;
use serde_json::Value;
use sqlx::sqlite::SqliteRow;
use sqlx::{query_file, SqlitePool};
use sqlx::{Column, Row, TypeInfo};
use std::collections::HashMap;
use std::sync::Arc;
use tiny_auth_business::password::{InPlacePasswordStore, Password};
use tracing::error;
use tracing::warn;

pub struct SqliteStore {
    pub(crate) name: String,
    pub(crate) read_pool: SqlitePool,
    pub(crate) write_pool: SqlitePool,
    pub(crate) in_place_password_store: Arc<InPlacePasswordStore>,
    pub(crate) user_data_assembler: DataAssembler,
    pub(crate) client_data_assembler: DataAssembler,
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

    pub(crate) async fn load_password(
        &self,
        id: i64,
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
}
