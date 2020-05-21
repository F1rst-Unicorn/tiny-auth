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

use crate::domain::user::User;
use crate::domain::client::Client;

use chrono::DateTime;
use chrono::Local;
use chrono::Duration;

pub trait UserStore: Send + Sync {
    fn get(&self, key: &str) -> Option<User>;
}

pub trait ClientStore: Send + Sync {
    fn get(&self, key: &str) -> Option<Client>;
}

pub trait AuthorizationCodeStore: Send + Sync {
    fn get_authorization_code(&self, client_id: &str, redirect_uri: &str, now: DateTime<Local>) -> String;

    fn validate(&self, client_id: &str, authorization_code: &str, now: DateTime<Local>) -> Option<(String, Duration)>;
}