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

use crate::client::Client;
use crate::oauth2::ClientType;
use crate::password::Password;
use serde::de::StdError;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,

    #[serde(with = "serde_yaml::with::singleton_map")]
    pub password: Password,

    #[serde(default)]
    pub allowed_scopes: BTreeMap<String, BTreeSet<String>>,

    #[serde(flatten)]
    pub attributes: HashMap<String, Value>,
}

impl User {
    pub fn get_allowed_scopes(&self, client_id: &str) -> BTreeSet<String> {
        self.allowed_scopes
            .get(client_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn merge(mut self, other: User) -> User {
        if let Password::Plain(_) = self.password {
            self.password = other.password;
        };

        for (client_id, mut other_scopes) in other.allowed_scopes {
            match self.allowed_scopes.get_mut(&client_id) {
                None => {
                    self.allowed_scopes.insert(client_id, other_scopes);
                }
                Some(scopes) => {
                    scopes.append(&mut other_scopes);
                }
            }
        }

        for (name, value) in other.attributes {
            match self.attributes.get_mut(&name) {
                None => {
                    self.attributes.insert(name, value);
                }
                _ => {
                    debug!("Ignoring duplicate attribute {name}");
                }
            }
        }
        self
    }
}

impl TryFrom<Client> for User {
    type Error = String;
    fn try_from(client: Client) -> Result<Self, Self::Error> {
        match client.client_type {
            ClientType::Public => Err("invalid client type".to_string()),
            ClientType::Confidential { password, .. } => Ok(Self {
                name: client.client_id,
                password,
                allowed_scopes: BTreeMap::default(),
                attributes: client.attributes,
            }),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const USER_1: &str = r#"
---
name: john
password:
  Pbkdf2HmacSha256:
    credential: iWUVg0T0npFqraL7frcoddhxQqkeL939abeUdq6LLMA=
    iterations: 100000
    salt: EkhhHSTv8lHJ0rICs1eRm88gw1KvyWs8D5x23M5+VYdqb2hu

email: john@test.example
email_verified: true
phone_number: +123456789
phone_number_verified: true
address: |
  Main Street 14
  11111 Portland
given_name: John
family_name: Doe
nickname: Jonny
preferred_username: doej
profile: ""
picture: ""
website: ""
gender: diverse
birthdate: 1991-09-11
zoneinfo: Europe/Berlin
locale: en-US
updated_at: 0
groups:
  - test
"#;

    pub fn get_test_user() -> User {
        serde_yaml::from_str(USER_1).unwrap()
    }
}
