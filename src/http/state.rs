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

use crate::store::AuthorizationCodeStore;
use crate::store::ClientStore;
use crate::store::UserStore;

use tera::Tera;

use jsonwebtoken::EncodingKey;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Algorithm;

pub struct State {
    pub instance: String,

    pub encoding_key: (EncodingKey, Algorithm),

    pub decoding_key: DecodingKey<'static>,

    pub tera: Tera,

    pub client_store: Box<dyn ClientStore>,

    pub user_store: Box<dyn UserStore>,

    pub auth_code_store: Box<dyn AuthorizationCodeStore>,
}

#[cfg(test)]
pub mod tests {
    use super::super::tera::load_template_engine;
    use super::*;

    pub fn build_test_state() -> State {
        let secret = "secret";
        State {
            instance: "https://localhost:8088".to_string(),
            encoding_key: (EncodingKey::from_secret(secret.as_bytes()), Algorithm::HS256),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()).into_static(),
            tera: load_template_engine(&(env!("CARGO_MANIFEST_DIR").to_string() + "/static/")),
            client_store: crate::store::tests::build_test_client_store(),
            user_store: crate::store::tests::build_test_user_store(),
            auth_code_store: crate::store::tests::build_test_auth_code_store(),
        }
    }
}
