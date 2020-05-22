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

use crate::domain::client::Client;
use crate::domain::user::User;

use chrono::DateTime;
use chrono::Duration;
use chrono::Local;

pub trait UserStore: Send + Sync {
    fn get(&self, key: &str) -> Option<User>;
}

pub trait ClientStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Client>;
}

pub trait AuthorizationCodeStore: Send + Sync {
    fn get_authorization_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        now: DateTime<Local>,
    ) -> String;

    fn validate(
        &self,
        client_id: &str,
        authorization_code: &str,
        now: DateTime<Local>,
    ) -> Option<(String, Duration)>;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::domain::client::Client;
    use crate::domain::user::User;
    use crate::protocol::oauth2::ClientType;

    struct TestUserStore {}

    impl UserStore for TestUserStore {
        fn get(&self, key: &str) -> Option<User> {
            match key {
                "user1" | "user2" | "user3" => Some(User {
                    name: key.to_string(),
                    password: key.to_string(),
                }),
                _ => None,
            }
        }
    }

    pub fn build_test_user_store() -> Box<impl UserStore> {
        Box::new(TestUserStore {})
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
                        password: "client1".to_string(),
                    },
                    redirect_uris: vec!["http://localhost/client1".to_string()],
                }),
                "client2" => Some(Client {
                    client_id: key.to_string(),
                    client_type: ClientType::Public,
                    redirect_uris: vec!["http://localhost/client2".to_string()],
                }),
                _ => None,
            }
        }
    }

    pub fn build_test_client_store() -> Box<impl ClientStore> {
        Box::new(TestClientStore {})
    }

    struct TestAuthorizationCodeStore {
        store: RefCell<HashMap<(String, String), (String, DateTime<Local>)>>,
    }

    unsafe impl Sync for TestAuthorizationCodeStore {}
    unsafe impl Send for TestAuthorizationCodeStore {}

    impl AuthorizationCodeStore for TestAuthorizationCodeStore {
        fn get_authorization_code(
            &self,
            client_id: &str,
            redirect_uri: &str,
            now: DateTime<Local>,
        ) -> String {
            self.store.borrow_mut().insert(
                (client_id.to_string(), now.to_rfc3339()),
                (redirect_uri.to_string(), now),
            );
            now.to_rfc3339()
        }

        fn validate(
            &self,
            client_id: &str,
            authorization_code: &str,
            now: DateTime<Local>,
        ) -> Option<(String, Duration)> {
            let (redirect_uri, creation_datetime) = self
                .store
                .borrow_mut()
                .remove(&(client_id.to_string(), authorization_code.to_string()))?;
            Some((redirect_uri, now.signed_duration_since(creation_datetime)))
        }
    }

    pub fn build_test_auth_code_store() -> Box<impl AuthorizationCodeStore> {
        Box::new(TestAuthorizationCodeStore {
            store: RefCell::new(HashMap::new()),
        })
    }
}
