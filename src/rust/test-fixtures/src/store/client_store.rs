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

use crate::data::client::{CONFIDENTIAL_CLIENT, PUBLIC_CLIENT, TINY_AUTH_FRONTEND};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::sync::Arc;
use tiny_auth_business::data::client::Client;
use tiny_auth_business::store::client_store::Error;
use tiny_auth_business::store::ClientStore;
use tokio::sync::RwLock;

pub const UNKNOWN_CLIENT_ID: &str = "unknown_client";

pub struct TestClientStore {
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
            CONFIDENTIAL_CLIENT.clone(),
            PUBLIC_CLIENT.clone(),
            TINY_AUTH_FRONTEND.clone(),
        ]
        .into_iter()
        .collect::<TestClientStore>(),
    )
}
