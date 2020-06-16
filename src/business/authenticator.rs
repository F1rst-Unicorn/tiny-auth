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

use crate::store::UserStore;

use std::boxed::Box;

use log::debug;

pub struct Authenticator {
    user_store: Box<dyn UserStore>,
}

impl Authenticator {
    pub fn new(user_store: Box<dyn UserStore>) -> Self {
        Self { user_store }
    }

    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        let user = match self.user_store.get(username) {
            None => {
                debug!("user '{}' not found", username);
                return false;
            }
            Some(u) => u,
        };

        if user.is_password_correct(password) {
            true
        } else {
            debug!("password of user '{}' wrong", username);
            false
        }
    }
}
