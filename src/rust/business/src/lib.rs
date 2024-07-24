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

pub mod authenticator;
pub mod authorize_endpoint;
pub mod change_password;
pub mod client;
pub mod clock;
pub mod consent;
pub mod cors;
pub mod health;
pub mod issuer_configuration;
pub mod jwk;
pub mod oauth2;
pub mod oidc;
pub mod password;
pub mod pkce;
pub mod rate_limiter;
pub mod scope;
pub mod serde;
pub mod store;
pub mod templater;
pub mod token;
pub mod token_endpoint;
pub mod user;
pub mod util;

pub mod test_fixtures {
    use crate::issuer_configuration::IssuerConfiguration;
    use crate::jwk::Jwk;
    use crate::rate_limiter::RateLimiter;
    use crate::token::TokenCreator;
    use crate::token::TokenValidator;
    use chrono::Duration;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::EncodingKey;
    use std::sync::Arc;

    pub fn build_test_token_creator() -> TokenCreator {
        TokenCreator::new(
            build_test_encoding_key(),
            build_test_issuer_config(),
            build_test_jwk(),
            Arc::new(crate::clock::test_fixtures::clock()),
            Duration::minutes(1),
            Duration::minutes(3),
        )
    }

    pub fn build_test_issuer_config() -> IssuerConfiguration {
        IssuerConfiguration {
            issuer_url: build_test_token_issuer(),
            algorithm: build_test_algorithm(),
        }
    }

    pub fn build_test_token_issuer() -> String {
        "https://localhost:8088".to_string()
    }

    fn build_test_algorithm() -> Algorithm {
        Algorithm::HS256
    }

    fn build_test_encoding_key() -> EncodingKey {
        EncodingKey::from_secret("secret".as_bytes())
    }

    pub fn build_test_rate_limiter() -> RateLimiter {
        RateLimiter::new(3, Duration::minutes(5))
    }

    pub fn build_test_decoding_key() -> DecodingKey {
        DecodingKey::from_secret("secret".as_bytes())
    }

    pub fn build_test_token_validator() -> TokenValidator {
        TokenValidator::new(
            build_test_decoding_key(),
            build_test_algorithm(),
            build_test_token_issuer(),
        )
    }

    pub fn build_test_jwk() -> Jwk {
        Jwk::new_rsa(
            "key_id".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        )
    }
}
