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

pub mod memory;

use crate::client::Client;
use crate::scope::Scope;
use crate::user::User;
use async_trait::async_trait;
use chrono::DateTime;
use chrono::Duration;
use chrono::Local;
use log::info;

pub trait UserStore: Send + Sync {
    fn get(&self, key: &str) -> Option<User>;
}

pub trait ClientStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Client>;
}

pub trait ScopeStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Scope>;

    fn get_all(&self, keys: &[String]) -> Vec<Scope> {
        keys.iter()
            .filter_map(|v| match self.get(v) {
                None => {
                    info!("requested unknown scope {}, ignoring", v);
                    None
                }
                s => s,
            })
            .collect()
    }

    fn get_scope_names(&self) -> Vec<String>;
}

// Recommended lifetime is 10 minutes
// https://tools.ietf.org/html/rfc6749#section-4.1.2
pub const AUTH_CODE_LIFE_TIME: i64 = 10;

pub struct AuthorizationCodeRecord {
    pub redirect_uri: String,

    pub stored_duration: Duration,

    pub username: String,

    pub scopes: String,

    pub auth_time: DateTime<Local>,

    pub nonce: Option<String>,
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn get_authorization_code(
        &self,
        client_id: &str,
        user: &str,
        redirect_uri: &str,
        scope: &str,
        now: DateTime<Local>,
        auth_time: DateTime<Local>,
        nonce: Option<String>,
    ) -> String;

    async fn validate(
        &self,
        client_id: &str,
        authorization_code: &str,
        now: DateTime<Local>,
    ) -> Option<AuthorizationCodeRecord>;
}

pub mod test_fixtures {
    use super::*;

    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::collections::HashMap;
    use std::iter::FromIterator;
    use std::sync::Arc;

    use crate::client::Client;
    use crate::oauth2::ClientType;
    use crate::password::Password;
    use crate::user::User;

    pub const UNKNOWN_USER: &str = "unknown_user";
    pub const USER: &str = "user1";

    struct TestUserStore {}

    impl UserStore for TestUserStore {
        fn get(&self, key: &str) -> Option<User> {
            match key {
                "user1" | "user2" | "user3" => Some(User {
                    name: key.to_string(),
                    password: Password::Plain(key.to_string()),
                    allowed_scopes: Default::default(),
                    attributes: HashMap::new(),
                }),
                _ => None,
            }
        }
    }

    pub fn build_test_user_store() -> Arc<impl UserStore> {
        Arc::new(TestUserStore {})
    }

    pub const UNKNOWN_CLIENT_ID: &str = "unknown_client";
    pub const CONFIDENTIAL_CLIENT: &str = "client1";
    pub const PUBLIC_CLIENT: &str = "client2";

    struct TestClientStore {}

    impl ClientStore for TestClientStore {
        fn get(&self, key: &str) -> Option<Client> {
            match key {
                "client1" => Some(Client {
                    client_id: key.to_string(),
                    client_type: ClientType::Confidential {
                        password: Password::Plain("client1".to_string()),
                        public_key: None,
                    },
                    redirect_uris: vec!["http://localhost/client1".to_string()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_string()]),
                    attributes: HashMap::new(),
                }),
                "client2" => Some(Client {
                    client_id: key.to_string(),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["http://localhost/client2".to_string()],
                    allowed_scopes: BTreeSet::from_iter(vec!["email".to_string()]),
                    attributes: HashMap::new(),
                }),
                _ => None,
            }
        }
    }

    pub fn build_test_client_store() -> Arc<impl ClientStore> {
        Arc::new(TestClientStore {})
    }

    struct TestScopeStore {}

    impl ScopeStore for TestScopeStore {
        fn get(&self, key: &str) -> Option<Scope> {
            Some(Scope::new(key, key, key))
        }
        fn get_scope_names(&self) -> Vec<String> {
            Vec::new()
        }
    }

    pub fn build_test_scope_store() -> Arc<impl ScopeStore> {
        Arc::new(TestScopeStore {})
    }

    type AuthCodeStoreKey = (String, String);
    type AuthCodeStoreValue = (
        String,
        String,
        String,
        DateTime<Local>,
        DateTime<Local>,
        Option<String>,
    );

    struct TestAuthorizationCodeStore {
        store: RefCell<HashMap<AuthCodeStoreKey, AuthCodeStoreValue>>,
    }

    unsafe impl Sync for TestAuthorizationCodeStore {}
    unsafe impl Send for TestAuthorizationCodeStore {}

    #[async_trait]
    impl AuthorizationCodeStore for TestAuthorizationCodeStore {
        #[allow(clippy::too_many_arguments)]
        async fn get_authorization_code(
            &self,
            client_id: &str,
            user: &str,
            redirect_uri: &str,
            scope: &str,
            now: DateTime<Local>,
            auth_time: DateTime<Local>,
            nonce: Option<String>,
        ) -> String {
            self.store.borrow_mut().insert(
                (client_id.to_string(), now.to_rfc3339()),
                (
                    redirect_uri.to_string(),
                    user.to_string(),
                    scope.to_string(),
                    now,
                    auth_time,
                    nonce,
                ),
            );
            now.to_rfc3339()
        }

        async fn validate(
            &self,
            client_id: &str,
            authorization_code: &str,
            now: DateTime<Local>,
        ) -> Option<AuthorizationCodeRecord> {
            let (redirect_uri, user, scope, creation_datetime, auth_time, nonce) = self
                .store
                .borrow_mut()
                .remove(&(client_id.to_string(), authorization_code.to_string()))?;
            Some(AuthorizationCodeRecord {
                redirect_uri,
                stored_duration: now.signed_duration_since(creation_datetime),
                username: user,
                scopes: scope,
                auth_time,
                nonce,
            })
        }
    }

    pub fn build_test_auth_code_store() -> Arc<impl AuthorizationCodeStore> {
        Arc::new(TestAuthorizationCodeStore {
            store: RefCell::new(HashMap::new()),
        })
    }
}
