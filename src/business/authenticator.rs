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

use crate::domain::Client;
use crate::domain::User;
use crate::store::UserStore;

use std::sync::Arc;

use log::debug;

#[derive(Clone)]
pub struct Authenticator {
    user_store: Arc<dyn UserStore>,

    pepper: String,
}

impl Authenticator {
    pub fn new(user_store: Arc<dyn UserStore>, pepper: &str) -> Self {
        Self {
            user_store,
            pepper: pepper.to_string(),
        }
    }

    pub fn authenticate_user_and_forget(&self, username: &str, password: &str) -> bool {
        self.authenticate_user(username, password).is_some()
    }

    pub fn authenticate_user(&self, username: &str, password: &str) -> Option<User> {
        let user = match self.user_store.get(username) {
            None => {
                debug!("user '{}' not found", username);
                return None;
            }
            Some(u) => u,
        };

        if user.is_password_correct(password, &self.pepper) {
            Some(user)
        } else {
            debug!("password of user '{}' wrong", username);
            None
        }
    }

    pub fn authenticate_client(&self, client: &Client, password: &str) -> bool {
        client.is_password_correct(password, &self.pepper)
    }
}
