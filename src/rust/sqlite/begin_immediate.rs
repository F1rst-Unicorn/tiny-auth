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

//! Needed until [this issue](https://github.com/launchbadge/sqlx/issues/481) is resolved to have
//! sqlite immediate transactions.

use sqlx::sqlite::SqliteQueryResult;
use sqlx::{Executor, SqliteConnection};
use std::future::Future;
use std::ops::{Deref, DerefMut};

pub(crate) trait SqliteConnectionExt {
    fn begin_immediate(&mut self) -> impl Future<Output = sqlx::Result<Transaction>>;
}

impl SqliteConnectionExt for SqliteConnection {
    async fn begin_immediate(&mut self) -> sqlx::Result<Transaction> {
        let conn = &mut *self;

        conn.execute("begin immediate;").await?;

        Ok(Transaction {
            conn,
            is_open: true,
        })
    }
}

pub(crate) struct Transaction<'c> {
    conn: &'c mut SqliteConnection,
    is_open: bool,
}

impl<'c> Transaction<'c> {
    pub(crate) async fn commit(mut self) -> sqlx::Result<SqliteQueryResult> {
        let res = self.conn.execute("commit;").await;

        if res.is_ok() {
            self.is_open = false;
        }

        res
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if self.is_open {
            let _ = futures::executor::block_on(self.execute("rollback;"));
        }
    }
}

impl Deref for Transaction<'_> {
    type Target = SqliteConnection;

    fn deref(&self) -> &Self::Target {
        self.conn
    }
}

impl DerefMut for Transaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn
    }
}
