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
use crate::clock::clock;
use crate::store::auth_code_store::build_test_auth_code_store;
use crate::store::client_store::build_test_client_store;
use crate::store::scope_store::build_test_scope_store;
use crate::store::user_store::build_test_user_store;
use crate::token::build_test_token_creator;
use tiny_auth_business::consent::{inject, Handler};

pub fn handler() -> impl Handler + 'static {
    inject::handler(
        build_test_scope_store(),
        build_test_user_store(),
        build_test_client_store(),
        build_test_auth_code_store(),
        build_test_token_creator(),
        clock(),
    )
}
