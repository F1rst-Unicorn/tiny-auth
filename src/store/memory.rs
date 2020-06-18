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

use crate::domain::client::Client;
use crate::domain::user::User;
use crate::protocol::oauth2::ClientType;
use crate::store::AuthorizationCodeRecord;
use crate::store::AuthorizationCodeStore;
use crate::store::ClientStore;
use crate::store::UserStore;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use tokio::sync::RwLock;

use chrono::DateTime;
use chrono::Local;

pub struct MemoryUserStore {}

impl UserStore for MemoryUserStore {
    fn get(&self, key: &str) -> Option<User> {
        Some(User {
            name: key.to_string(),
            password: key.to_string(),
            attributes: HashMap::new(),
        })
    }
}

pub struct MemoryClientStore {}

impl ClientStore for MemoryClientStore {
    fn get(&self, key: &str) -> Option<Client> {
        Some(Client {
            client_id: key.to_string(),
            client_type: ClientType::Public,
            redirect_uris: vec!["http://localhost/client".to_string()],
            attributes: HashMap::new(),
        })
    }
}

#[derive(PartialEq, Eq, Hash)]
struct AuthCodeKey {
    client_id: String,

    authorization_code: String,
}

struct AuthCodeValue {
    redirect_uri: String,

    user: String,

    insertion_time: DateTime<Local>,
}

pub struct MemoryAuthorizationCodeStore {
    store: Arc<RwLock<HashMap<AuthCodeKey, AuthCodeValue>>>,
}

impl Default for MemoryAuthorizationCodeStore {
    fn default() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl AuthorizationCodeStore for MemoryAuthorizationCodeStore {
    async fn get_authorization_code(
        &self,
        client_id: &str,
        user: &str,
        redirect_uri: &str,
        now: DateTime<Local>,
    ) -> String {
        let auth_code = crate::util::generate_random_string(32);
        let mut store = self.store.write().await;

        store.insert(
            AuthCodeKey {
                client_id: client_id.to_string(),
                authorization_code: auth_code.clone(),
            },
            AuthCodeValue {
                redirect_uri: redirect_uri.to_string(),
                user: user.to_string(),
                insertion_time: now,
            },
        );

        auth_code
    }

    async fn validate(
        &self,
        client_id: &str,
        authorization_code: &str,
        now: DateTime<Local>,
    ) -> Option<AuthorizationCodeRecord> {
        let mut store = self.store.write().await;

        let value = store.remove(&AuthCodeKey {
            client_id: client_id.to_string(),
            authorization_code: authorization_code.to_string(),
        })?;

        Some(AuthorizationCodeRecord {
            redirect_uri: value.redirect_uri.clone(),
            stored_duration: now.signed_duration_since(value.insertion_time),
            username: value.user,
        })
    }
}
