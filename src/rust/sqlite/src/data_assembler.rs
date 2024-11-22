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
use crate::error::SqliteError;
use crate::store::SqliteStore;
use serde_json::Value;
use sqlx::sqlite::SqliteRow;
use sqlx::{Column, Row, TypeInfo};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tiny_auth_business::data_loader::{
    load_client, load_user, DataLoader, LoadedData, Multiplicity,
};
use tiny_auth_business::template::data_loader::DataLoaderContext;
use tiny_auth_business::template::Templater;
use tracing::{error, instrument, warn};

const ID_COLUMN_NAME: &str = "tiny_auth_id";
const ASSIGNMENT_COLUMN_NAME: &str = "tiny_auth_assigned_to";

pub struct QueryLoader {
    pub(crate) data_loader: DataLoader,
    pub(crate) query: String,
    pub(crate) assignment_query: String,
}

impl QueryLoader {
    pub(crate) async fn load_data<'a>(
        &self,
        transaction: &mut Transaction<'_>,
        templater: Arc<dyn Templater<DataLoaderContext<'a>>>,
        context: DataLoaderContext<'a>,
    ) -> Result<LoadedData, SqliteError> {
        let query = templater.instantiate_by_name(
            context,
            self.data_loader.name.as_str(),
            self.query.as_str(),
        )?;

        let data = sqlx::query(query.as_ref())
            .fetch_all(&mut **transaction)
            .await?;

        if data.is_empty() {
            return Ok(LoadedData::default());
        }

        let first_row = &data[0];
        if !Self::is_int_column_present(first_row, ID_COLUMN_NAME) {
            return Ok(LoadedData::default());
        }

        let assignment_is_embedded = first_row.try_column(ASSIGNMENT_COLUMN_NAME).is_ok();

        let mut loaded_data = BTreeMap::default();
        let mut assignments = BTreeMap::default();
        for row in data {
            let id = row.get(ID_COLUMN_NAME);

            if assignment_is_embedded {
                let assigned_to = row.get(ASSIGNMENT_COLUMN_NAME);
                assignments
                    .entry(assigned_to)
                    .and_modify(|set: &mut Vec<i32>| {
                        set.push(id);
                    })
                    .or_insert_with(|| vec![id]);
            }

            let entry = SqliteStore::map_attributes(row, &[ID_COLUMN_NAME, ASSIGNMENT_COLUMN_NAME]);
            loaded_data.insert(id, entry.into_iter().collect());
        }

        if !assignment_is_embedded {
            let assignment_query = templater.instantiate_by_name(
                context,
                self.data_loader.name.as_str(),
                self.assignment_query.as_str(),
            )?;
            let assignment_data = sqlx::query(assignment_query.as_ref())
                .fetch_all(&mut **transaction)
                .await?;

            if assignment_data.is_empty() {
                return Ok(LoadedData::default());
            }

            let first_row = &assignment_data[0];
            if !Self::is_int_column_present(first_row, ID_COLUMN_NAME) {
                return Ok(LoadedData::default());
            }

            if !Self::is_int_column_present(first_row, ASSIGNMENT_COLUMN_NAME) {
                return Ok(LoadedData::default());
            }

            for row in assignment_data {
                let id = row.get(ID_COLUMN_NAME);
                let assigned_to = row.get(ASSIGNMENT_COLUMN_NAME);
                assignments
                    .entry(assigned_to)
                    .and_modify(|set| {
                        set.push(id);
                    })
                    .or_insert_with(|| vec![id]);
            }
        }

        Ok(LoadedData::new(loaded_data, assignments))
    }

    fn is_int_column_present(first_row: &SqliteRow, column: &str) -> bool {
        let assigned_to = match first_row.try_column(column) {
            Err(e) => {
                error!(%e, "assignment contains no {column}, ignoring");
                return false;
            }
            Ok(v) => v,
        };

        if !assigned_to
            .type_info()
            .name()
            .to_lowercase()
            .starts_with("int")
        {
            error!("{column} is not an integer, ignoring");
            return false;
        }
        true
    }
}

pub struct DataAssembler {
    pub(crate) query_loaders: Vec<QueryLoader>,
    pub(crate) templater: Arc<dyn for<'a> Templater<DataLoaderContext<'a>>>,
}

#[derive(Clone, Copy)]
pub(crate) enum Root {
    User,
    Client,
}

impl AsRef<str> for Root {
    fn as_ref(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Client => "client",
        }
    }
}

impl DataAssembler {
    pub(crate) async fn load(
        &self,
        root: Value,
        id: i32,
        transaction: &mut Transaction<'_>,
        root_type: Root,
    ) -> Result<HashMap<String, Value>, SqliteError> {
        let mut loaded_data = Vec::new();
        let mut ids: BTreeMap<&str, Vec<i32>> = BTreeMap::default();
        let mut already_loaded_data: BTreeMap<String, Value> = BTreeMap::default();
        let mut transitive_multiplicity = BTreeMap::default();
        ids.insert(root_type.as_ref(), vec![id]);
        already_loaded_data.insert(root_type.as_ref().to_string(), root.clone());
        transitive_multiplicity.insert(root_type.as_ref(), Multiplicity::ToOne);

        for query_loader in &self.query_loaders {
            self.load_from_single(
                query_loader,
                &mut loaded_data,
                &mut ids,
                &mut already_loaded_data,
                &mut transitive_multiplicity,
                transaction,
            )
            .await;
        }
        drop(ids);
        drop(transitive_multiplicity);
        drop(already_loaded_data);

        if loaded_data.len() != self.query_loaders.len() {
            return Err(SqliteError::BackendError);
        }

        let loader = match root_type {
            Root::User => load_user,
            Root::Client => load_client,
        };

        let data = loader(
            self.query_loaders
                .iter()
                .map(|v| v.data_loader.clone())
                .collect(),
            loaded_data,
            root,
            id,
        );

        let attributes = if let Value::Object(map) = data {
            map.into_iter().collect()
        } else {
            HashMap::default()
        };

        Ok(attributes)
    }

    #[instrument(skip_all, fields(data_loader = %query_loader.data_loader.name))]
    async fn load_from_single<'a>(
        &self,
        query_loader: &'a QueryLoader,
        loaded_data: &mut Vec<LoadedData>,
        ids: &mut BTreeMap<&'a str, Vec<i32>>,
        already_loaded_data: &mut BTreeMap<String, Value>,
        transitive_multiplicity: &mut BTreeMap<&'a str, Multiplicity>,
        transaction: &mut Transaction<'_>,
    ) {
        let Some(destination) = query_loader.data_loader.location.first() else {
            warn!("location has no first element so it cannot be nested");
            return;
        };
        let Some(destination_ids) = ids.get(destination) else {
            warn!(%destination,
                "data loader will be ignored as destination is not known. \
                Maybe the order is wrong."
            );
            return;
        };
        let context = DataLoaderContext {
            assigned_to: destination_ids,
            loaded_data: already_loaded_data,
        };

        let single_loaded_data = match query_loader
            .load_data(transaction, self.templater.clone(), context)
            .await
        {
            Err(e) => {
                warn!(%e, "failed to load data");
                return;
            }
            Ok(v) => v,
        };

        ids.insert(
            query_loader.data_loader.name.as_str(),
            single_loaded_data.data.keys().cloned().collect(),
        );
        let current_transitive_multiplicity = match (
            transitive_multiplicity
                .get(destination)
                .cloned()
                .unwrap_or(Multiplicity::ToMany),
            query_loader.data_loader.multiplicity,
        ) {
            (Multiplicity::ToMany, _) => Multiplicity::ToMany,
            (Multiplicity::ToOne, v) => v,
        };
        transitive_multiplicity.insert(
            query_loader.data_loader.name.as_str(),
            current_transitive_multiplicity,
        );
        match current_transitive_multiplicity {
            Multiplicity::ToOne => {
                already_loaded_data.insert(
                    query_loader.data_loader.name.clone(),
                    single_loaded_data
                        .data
                        .first_key_value()
                        .map(|(_, v)| v.clone())
                        .unwrap_or(Value::Null),
                );
            }
            Multiplicity::ToMany => {
                already_loaded_data.insert(
                    query_loader.data_loader.name.clone(),
                    single_loaded_data.data.values().cloned().collect::<Value>(),
                );
            }
        }
        loaded_data.push(single_loaded_data);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::begin_immediate::SqliteConnectionExt;
    use pretty_assertions::assert_eq;
    use rstest::{fixture, rstest};
    use sqlx::pool::PoolOptions;
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::sqlite::SqliteJournalMode::Wal;
    use sqlx::sqlite::SqliteSynchronous::Normal;
    use sqlx::ConnectOptions;
    use sqlx::{Pool, Sqlite};
    use std::str::FromStr;
    use std::time::Duration;
    use test_log::test;
    use tiny_auth_business::data_loader::Multiplicity;
    use tiny_auth_business::template::test_fixtures::TestTemplater;
    use tracing::log::LevelFilter;

    #[rstest]
    #[test(tokio::test)]
    async fn missing_id_column_is_ignored(#[future] db: Pool<Sqlite>) {
        let db = db.await;
        let mut conn = db.acquire().await.unwrap();
        let mut transaction = conn.begin_immediate().await.unwrap();
        let uut = QueryLoader {
            data_loader: DataLoader {
                name: "desk".to_string(),
                location: "/user/desk".try_into().unwrap(),
                multiplicity: Multiplicity::ToOne,
            },
            query: "select * from test_data_desk".to_string(),
            assignment_query: "".to_string(),
        };
        let data_loader_context = DataLoaderContext {
            assigned_to: &[],
            loaded_data: &BTreeMap::default(),
        };

        let actual = uut
            .load_data(
                &mut transaction,
                Arc::new(TestTemplater::default()),
                data_loader_context,
            )
            .await;

        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), LoadedData::default());
    }

    #[rstest]
    #[test(tokio::test)]
    async fn id_column_of_wrong_type_is_ignored(#[future] db: Pool<Sqlite>) {
        let db = db.await;
        let mut conn = db.acquire().await.unwrap();
        let mut transaction = conn.begin_immediate().await.unwrap();
        let uut = QueryLoader {
            data_loader: DataLoader {
                name: "desk".to_string(),
                location: "/user/desk".try_into().unwrap(),
                multiplicity: Multiplicity::ToOne,
            },
            query: "select material as tiny_auth_id from test_data_desk".to_string(),
            assignment_query: "".to_string(),
        };
        let data_loader_context = DataLoaderContext {
            assigned_to: &[],
            loaded_data: &BTreeMap::default(),
        };

        let actual = uut
            .load_data(
                &mut transaction,
                Arc::new(TestTemplater::default()),
                data_loader_context,
            )
            .await;

        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), LoadedData::default());
    }

    #[rstest]
    #[test(tokio::test)]
    async fn db_error_is_propagated(#[future] db: Pool<Sqlite>) {
        let db = db.await;
        let mut conn = db.acquire().await.unwrap();
        let mut transaction = conn.begin_immediate().await.unwrap();
        let uut = DataAssembler {
            query_loaders: vec![QueryLoader {
                data_loader: DataLoader {
                    name: "desk".to_string(),
                    location: "/user/desk".try_into().unwrap(),
                    multiplicity: Multiplicity::ToOne,
                },
                query: "select * from non_existing_table".to_string(),
                assignment_query: "".to_string(),
            }],
            templater: Arc::new(TestTemplater),
        };

        let actual = uut
            .load(Default::default(), 1, &mut transaction, Root::User)
            .await;

        assert!(actual.is_err());
    }

    #[fixture]
    async fn db() -> Pool<Sqlite> {
        let options = SqliteConnectOptions::from_str(
            &(env!("CARGO_MANIFEST_DIR").to_string() + "/../../sql/sqlite/build/unittests.sqlite"),
        )
        .unwrap()
        .read_only(false)
        .journal_mode(Wal)
        .busy_timeout(Duration::from_secs(5))
        .synchronous(Normal)
        .pragma("cache_size", "1000000000")
        .foreign_keys(true)
        .pragma("temp_store", "memory")
        .analysis_limit(Some(0))
        .optimize_on_close(true, None)
        .log_statements(LevelFilter::Trace);
        let pool_options = PoolOptions::new()
            .min_connections(0)
            .max_lifetime(Some(Duration::from_secs(600)));

        let write_pool_options = pool_options.max_connections(1);
        write_pool_options.connect_lazy_with(options)
    }
}
