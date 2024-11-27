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
use std::sync::Arc;
use tiny_auth_business::data::password::{DispatchingPasswordStore, InPlacePasswordStore};

pub const PEPPER: &str = "pepper";

pub fn in_place_password_store() -> InPlacePasswordStore {
    InPlacePasswordStore {
        pepper: PEPPER.to_owned(),
    }
}

pub fn dispatching_password_store() -> DispatchingPasswordStore {
    tiny_auth_business::data::password::inject::dispatching_password_store(
        Default::default(),
        Arc::new(in_place_password_store()),
    )
}
