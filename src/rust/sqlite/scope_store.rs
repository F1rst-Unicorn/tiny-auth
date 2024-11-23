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
use itertools::Itertools;
use serde_json::Value;
use sqlx::query_file;
use std::collections::{BTreeMap, BTreeSet};
use std::iter::repeat;
use tiny_auth_business::json_pointer::JsonPointer;
use tiny_auth_business::scope::{Destination, Mapping, Scope, Type};
use tiny_auth_business::store::{ScopeStore, ScopeStoreError};
use tiny_auth_business::util::wrap_err;
use tracing::{error, span, Level};
use tracing::{instrument, warn};

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
                                                if let Some(v) = value.pointer_mut(String::from(pointer).as_str()) {
                                                *v = map_value_by_type(
                                                    plain_mapping.value.as_str(),
                                                    plain_mapping.r#type.as_str());
                                                }
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
                                                if let Some(v) = value.pointer_mut(String::from(pointer).as_str()) {
                                                    *v = template_mapping.template.clone().into();
                                                }
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
