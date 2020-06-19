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
use crate::protocol::oauth2::ClientType;

use std::collections::HashMap;
use std::convert::TryFrom;

use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct User {
    pub name: String,

    pub password: String,

    #[serde(flatten)]
    pub attributes: HashMap<String, String>,
}

impl User {
    pub fn is_password_correct(&self, password: &str) -> bool {
        self.password == password
    }
}

impl TryFrom<Client> for User {
    type Error = String;
    fn try_from(client: Client) -> Result<Self, Self::Error> {
        match client.client_type {
            ClientType::Public => Err("invalid client type".to_string()),
            ClientType::Confidential { password } => Ok(Self {
                name: client.client_id,
                password,
                attributes: client.attributes,
            }),
        }
    }
}
