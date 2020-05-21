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

use crate::domain::user::User;
use crate::store::UserStore;
use crate::store::ClientStore;
use crate::domain::client::Client;

pub struct MemoryUserStore {}

impl UserStore for MemoryUserStore {
    fn get(&self, key: &str) -> Option<User> {
        Some(User {
            name: key.to_string(),
            password: "".to_string(),
        })
    }
}

pub struct MemoryClientStore {}

impl ClientStore for MemoryClientStore {
    fn get(&self, key: &str) -> Option<Client> {
        Some(Client {
            client_id: key.to_string(),
            redirect_uris: vec!("http://localhost/client".to_string()),
        })
    }
}