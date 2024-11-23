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
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};
use tiny_auth_business::store::UserStore;
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;
use tracing::instrument;

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
        let user_as_value = serde_json::to_value(user_as_value).map_err(wrap_err)?;
        user.attributes = self
            .user_data_assembler
            .load(user_as_value, user_id, &mut transaction, Root::User)
            .await
            .map_err(wrap_err)?;
        transaction.commit().await.map_err(wrap_err)?;

        Ok(user)
    }
}

impl SqliteStore {
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
}
