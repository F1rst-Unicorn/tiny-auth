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

use crate::protocol::oauth2::ClientType;

use std::collections::HashMap;

use serde::Deserialize;
use serde::Serialize;

use serde_json::Value;

use log::error;

#[derive(Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,

    pub client_type: ClientType,

    pub redirect_uris: Vec<String>,

    #[serde(flatten)]
    pub attributes: HashMap<String, Value>,
}

impl Client {
    pub fn is_redirect_uri_valid(&self, uri: &str) -> bool {
        self.redirect_uris.contains(&uri.to_string())
    }

    pub fn is_password_correct(&self, password: &str, pepper: &str) -> bool {
        match &self.client_type {
            ClientType::Public => {
                error!("verified password on public client '{}'", self.client_id);
                panic!("verified password on public client");
            }

            ClientType::Confidential {
                password: stored_password,
            } => stored_password.verify(&self.client_id, password, pepper),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const CLIENT_1: &str = r#"
---
client_id: confidential
client_type:
  confidential:
    password:
      Pbkdf2HmacSha256:
        credential: yIwGQgK7dU7LKxageOikUK1Ci8LekYLAUqsUQqKgBXk=
        iterations: 100000
        salt: GDyTkeq//lzzWvEd6JJn8Eu227floAeFemr+4oAsXA1jb25maWRlbnRpYWw=

redirect_uris:
  - http://localhost/confidential
"#;

    pub fn get_test_client() -> Client {
        serde_yaml::from_str(CLIENT_1).unwrap()
    }
}
