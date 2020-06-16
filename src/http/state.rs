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

#[cfg(test)]
pub mod tests {
    use super::super::tera::load_template_engine;
    use crate::business::authenticator::Authenticator;
    use crate::business::token::TokenCreator;
    use crate::store::AuthorizationCodeStore;
    use crate::store::ClientStore;
    use crate::store::UserStore;

    use actix_web::web::Data;

    use jsonwebtoken::Algorithm;
    use jsonwebtoken::EncodingKey;

    use tera::Tera;

    pub fn build_test_token_creator() -> Data<TokenCreator> {
        Data::new(TokenCreator::new(
            build_test_encoding_key(),
            build_test_algorithm(),
            build_test_token_issuer(),
        ))
    }

    fn build_test_token_issuer() -> String {
        "https://localhost:8088".to_string()
    }

    fn build_test_algorithm() -> Algorithm {
        Algorithm::HS256
    }

    fn build_test_encoding_key() -> EncodingKey {
        EncodingKey::from_secret("secret".as_bytes())
    }

    pub fn build_test_tera() -> Data<Tera> {
        Data::new(load_template_engine(
            &(env!("CARGO_MANIFEST_DIR").to_string() + "/static/"),
        ))
    }

    pub fn build_test_client_store() -> Data<Box<dyn ClientStore>> {
        Data::new(crate::store::tests::build_test_client_store())
    }

    pub fn build_test_user_store() -> Data<Box<dyn UserStore>> {
        Data::new(crate::store::tests::build_test_user_store())
    }

    pub fn build_test_auth_code_store() -> Data<Box<dyn AuthorizationCodeStore>> {
        Data::new(crate::store::tests::build_test_auth_code_store())
    }

    pub fn build_test_authenticator() -> Data<Authenticator> {
        Data::new(Authenticator::new(
            crate::store::tests::build_test_user_store(),
        ))
    }
}
