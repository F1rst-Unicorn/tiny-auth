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
use sqlx::{Column, Error, Row, TypeInfo};
use std::collections::{BTreeMap, HashMap};
use tiny_auth_business::data_loader::{DataLoader, LoadedData};
use tracing::{error, instrument, warn};

const ID_COLUMN_NAME: &str = "tiny_auth_id";
const ASSIGNMENT_COLUMN_NAME: &str = "tiny_auth_assigned_to";

pub struct QueryLoader {
    pub(crate) data_loader: DataLoader,
    pub(crate) query: String,
    pub(crate) assignment_query: String,
}

impl QueryLoader {
    #[instrument(skip_all, fields(data_loader = self.data_loader.name))]
    pub async fn load_data(&self, transaction: &mut Transaction<'_>) -> Result<LoadedData, Error> {
        let data = sqlx::query(self.query.as_str())
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
            let assignment_data = sqlx::query(self.assignment_query.as_str())
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

#[derive(Default)]
pub struct DataAssembler {
    pub(crate) data_loaders: Vec<QueryLoader>,
}

impl DataAssembler {
    pub(crate) async fn load(
        &self,
        mut attributes: HashMap<String, Value>,
        user_id: i32,
        transaction: &mut Transaction<'_>,
        loader: fn(Vec<DataLoader>, Vec<LoadedData>, Value, i32) -> Value,
    ) -> Result<HashMap<String, Value>, SqliteError> {
        let mut loaded_data = Vec::new();
        for data_loader in &self.data_loaders {
            loaded_data.push((data_loader, data_loader.load_data(transaction).await))
        }

        let (loaded_data, errors): (Vec<_>, Vec<_>) =
            loaded_data.into_iter().partition(|(_, data)| data.is_ok());

        let any_errors = !errors.is_empty();
        errors
            .into_iter()
            .map(|(data_loader, e)| (data_loader, e.unwrap_err()))
            .for_each(
                |(data_loader, e)| warn!(%e, data_loader = data_loader.data_loader.name, "failed to load data"),
            );

        if any_errors {
            return Err(SqliteError::BackendError);
        }

        let loaded_data = loaded_data.into_iter().map(|v| v.1.unwrap()).collect();

        let data = loader(
            self.data_loaders
                .iter()
                .map(|v| v.data_loader.clone())
                .collect(),
            loaded_data,
            attributes.into_iter().collect(),
            user_id,
        );

        if let Value::Object(map) = data {
            attributes = map.into_iter().collect();
        } else {
            attributes = HashMap::default();
        }

        Ok(attributes)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::begin_immediate::SqliteConnectionExt;
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
    use tiny_auth_business::data_loader::{load_user, Multiplicity};
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

        let actual = uut.load_data(&mut transaction).await;

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

        let actual = uut.load_data(&mut transaction).await;

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
            data_loaders: vec![QueryLoader {
                data_loader: DataLoader {
                    name: "desk".to_string(),
                    location: "/user/desk".try_into().unwrap(),
                    multiplicity: Multiplicity::ToOne,
                },
                query: "select * from non_existing_table".to_string(),
                assignment_query: "".to_string(),
            }],
        };

        let actual = uut
            .load(Default::default(), 1, &mut transaction, load_user)
            .await;

        assert!(actual.is_err());
    }

    #[rstest]
    #[test(tokio::test)]
    async fn loader_returning_non_object_gives_empty_attributes(#[future] db: Pool<Sqlite>) {
        let db = db.await;
        let mut conn = db.acquire().await.unwrap();
        let mut transaction = conn.begin_immediate().await.unwrap();
        let uut = DataAssembler {
            data_loaders: vec![],
        };

        let actual = uut
            .load(Default::default(), 1, &mut transaction, null_loader)
            .await;

        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), Default::default());
    }

    fn null_loader(_: Vec<DataLoader>, _: Vec<LoadedData>, _: Value, _: i32) -> Value {
        Value::Null
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
