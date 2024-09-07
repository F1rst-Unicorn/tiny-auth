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
use crate::error::SqliteError;
use crate::store::SqliteStore;
use sqlx::pool::PoolOptions;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::sqlite::SqliteJournalMode::Wal;
use sqlx::sqlite::SqliteSynchronous::Normal;
use sqlx::{ConnectOptions, Executor};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::log::LevelFilter;

pub async fn sqlite_store(name: &str, url: &str) -> Result<Arc<SqliteStore>, SqliteError> {
    let options = SqliteConnectOptions::from_str(url)?
        .read_only(true)
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

    let read_pool_options = pool_options.clone().max_connections(4);
    let read_pool = read_pool_options.connect_lazy_with(options.clone());

    let write_options = options.read_only(false);
    let write_pool_options = pool_options.max_connections(1);
    let write_pool = write_pool_options.connect_lazy_with(write_options);

    write_pool.execute("pragma wal_checkpoint(full)").await?;
    write_pool.execute("analyze").await?;
    write_pool.execute("pragma optimize").await?;

    Ok(Arc::new(SqliteStore {
        name: String::from(name),
        read_pool,
        write_pool,
    }))
}
