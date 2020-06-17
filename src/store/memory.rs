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

use chrono::DateTime;
use chrono::Duration;
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

pub struct MemoryAuthorizationCodeStore {}

impl AuthorizationCodeStore for MemoryAuthorizationCodeStore {
    fn get_authorization_code(
        &self,
        client_id: &str,
        user: &str,
        redirect_uri: &str,
        now: DateTime<Local>,
    ) -> String {
        "dummy_code".to_string()
    }

    fn validate(
        &self,
        client_id: &str,
        authorization_code: &str,
        now: DateTime<Local>,
    ) -> Option<AuthorizationCodeRecord> {
        Some(AuthorizationCodeRecord {
            redirect_uri: "http://localhost/client".to_string(),
            stored_duration: Duration::seconds(1),
            username: "user".to_string(),
        })
    }
}
