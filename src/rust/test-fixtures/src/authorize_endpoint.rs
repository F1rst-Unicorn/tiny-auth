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
use crate::store::client_store::build_test_client_store;
use tiny_auth_business::authorize_endpoint::{inject, AuthorizeRequestState, Handler};
use url::Url;

pub fn handler() -> Handler {
    inject::handler(build_test_client_store())
}

pub fn test_request() -> AuthorizeRequestState {
    AuthorizeRequestState {
        client_id: "".to_owned(),
        scopes: vec![],
        prompts: vec![],
        redirect_uri: Url::parse("http://localhost/client").unwrap(),
        state: None,
        nonce: None,
        max_age: None,
        login_hint: None,
        encode_redirect_to_fragment: false,
        response_types: vec![],
        code_challenge: None,
    }
}
