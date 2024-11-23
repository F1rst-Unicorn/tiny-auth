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
use async_trait::async_trait;
use sqlx::SqlitePool;
use tiny_auth_business::health::HealthCheckCommand;
use tracing::warn;

pub struct SqliteHealth {
    pub(crate) read_pool: SqlitePool,
}

#[async_trait]
impl HealthCheckCommand for SqliteHealth {
    async fn check(&self) -> bool {
        let mut conn = match self.read_pool.acquire().await {
            Err(e) => {
                warn!(%e, "failed to acquire connection");
                return false;
            }
            Ok(v) => v,
        };
        let mut transaction = match conn.begin_immediate().await {
            Err(e) => {
                warn!(%e, "failed to begin transaction");
                return false;
            }
            Ok(v) => v,
        };

        1 == match sqlx::query_file_scalar!("queries/check-health.sql")
            .fetch_one(&mut *transaction)
            .await
        {
            Err(e) => {
                warn!(%e, "failed to check health");
                return false;
            }
            Ok(v) => {
                if let Err(e) = transaction.commit().await {
                    warn!(%e, "failed to commit");
                    return false;
                }
                v
            }
        }
    }
}
