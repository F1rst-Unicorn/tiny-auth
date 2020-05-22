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

use log::error;

pub struct Client {
    pub client_id: String,

    pub client_type: ClientType,

    pub redirect_uris: Vec<String>,
}

impl Client {
    pub fn is_redirect_uri_valid(&self, uri: &str) -> bool {
        self.redirect_uris.contains(&uri.to_string())
    }

    pub fn is_password_correct(&self, password: &str) -> bool {
        match &self.client_type {
            ClientType::Public => {
                error!("verified password on public client '{}'", self.client_id);
                true
            },

            ClientType::Confidential{password: stored_password} => {
                stored_password == password
            }
        }
    }
}