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

use crate::data::client::Client;
use crate::store::client_store::Error as ClientError;
use async_trait::async_trait;
use futures_util::future::join_all;
use serde::de::StdError;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, Level};

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Client, Error>;
}

pub struct MergingClientStore {
    stores: Vec<Arc<dyn ClientStore>>,
}

impl From<Vec<Arc<dyn ClientStore>>> for MergingClientStore {
    fn from(value: Vec<Arc<dyn ClientStore>>) -> Self {
        Self { stores: value }
    }
}

#[async_trait]
impl ClientStore for MergingClientStore {
    #[instrument(level = Level::DEBUG, name = "get_client", skip_all)]
    async fn get(&self, key: &str) -> Result<Client, ClientError> {
        let results: Vec<_> = join_all(self.stores.iter().map(|v| v.get(key)))
            .await
            .into_iter()
            .collect();

        if let Some(Err(error)) = results.iter().find(|v| {
            matches!(
                v,
                Err(ClientError::BackendError | ClientError::BackendErrorWithContext(_))
            )
        }) {
            return Err(error.clone());
        }

        results
            .into_iter()
            .filter_map(Result::ok)
            .reduce(Client::merge)
            .inspect(|_| debug!("found"))
            .ok_or(ClientError::NotFound)
    }
}

pub mod test_fixtures {
    use super::*;

    use crate::data::client::Client;
    use std::collections::BTreeMap;
    use std::iter::FromIterator;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    pub const UNKNOWN_CLIENT_ID: &str = "unknown_client";

    struct TestClientStore {
        clients: RwLock<BTreeMap<String, Client>>,
    }

    impl FromIterator<Client> for TestClientStore {
        fn from_iter<T: IntoIterator<Item = Client>>(iter: T) -> Self {
            Self {
                clients: RwLock::new(
                    iter.into_iter()
                        .map(|v| (v.client_id.to_owned(), v))
                        .collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl ClientStore for TestClientStore {
        async fn get(&self, key: &str) -> Result<Client, Error> {
            self.clients
                .read()
                .await
                .get(key)
                .cloned()
                .ok_or(Error::NotFound)
        }
    }

    pub fn build_test_client_store() -> Arc<impl ClientStore> {
        Arc::new(
            [
                crate::data::client::test_fixtures::CONFIDENTIAL_CLIENT.clone(),
                crate::data::client::test_fixtures::PUBLIC_CLIENT.clone(),
                crate::data::client::test_fixtures::TINY_AUTH_FRONTEND.clone(),
            ]
            .into_iter()
            .collect::<TestClientStore>(),
        )
    }
}
