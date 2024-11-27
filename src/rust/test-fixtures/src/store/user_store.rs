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

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::sync::Arc;
use tiny_auth_business::data::password::Password;
use tiny_auth_business::data::user::User;
use tiny_auth_business::store::user_store::Error;
use tiny_auth_business::store::UserStore;
use tokio::sync::RwLock;

pub struct TestUserStore {
    users: RwLock<BTreeMap<String, User>>,
}

impl FromIterator<User> for TestUserStore {
    fn from_iter<T: IntoIterator<Item = User>>(iter: T) -> Self {
        Self {
            users: RwLock::new(iter.into_iter().map(|v| (v.name.to_owned(), v)).collect()),
        }
    }
}

#[async_trait]
impl UserStore for TestUserStore {
    async fn get(&self, key: &str) -> Result<User, Error> {
        self.users
            .read()
            .await
            .get(key)
            .cloned()
            .ok_or(Error::NotFound)
    }
}

pub const UNKNOWN_USER: &str = "unknown_user";
pub const USER: &str = "user1";

pub fn build_test_user_store() -> Arc<impl UserStore> {
    Arc::new(
        [
            User {
                name: USER.to_owned(),
                password: Password::Plain(USER.to_owned()),
                allowed_scopes: Default::default(),
                attributes: HashMap::new(),
            },
            User {
                name: "user2".to_owned(),
                password: Password::Plain("user2".to_owned()),
                allowed_scopes: Default::default(),
                attributes: HashMap::new(),
            },
            User {
                name: "user3".to_owned(),
                password: Password::Plain("user3".to_owned()),
                allowed_scopes: Default::default(),
                attributes: HashMap::new(),
            },
        ]
        .into_iter()
        .collect::<TestUserStore>(),
    )
}
