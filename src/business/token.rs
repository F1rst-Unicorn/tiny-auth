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

use crate::domain::token::Token;

use jsonwebtoken::decode;
use jsonwebtoken::encode;
use jsonwebtoken::errors::Result;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::Validation;

use log::debug;

#[derive(Clone)]
pub struct TokenCreator {
    key: EncodingKey,

    algorithm: Algorithm,

    issuer: String,
}

impl TokenCreator {
    pub fn new(key: EncodingKey, algorithm: Algorithm, issuer: String) -> Self {
        Self {
            key,
            algorithm,
            issuer,
        }
    }

    pub fn create(&self, mut token: Token) -> Result<String> {
        token.issuer = self.issuer.clone();
        encode(&Header::new(self.algorithm), &token, &self.key)
    }
}

#[derive(Clone)]
pub struct TokenValidator {
    key: DecodingKey<'static>,

    validation: Validation,
}

impl TokenValidator {
    pub fn new(key: DecodingKey<'static>, algorithm: Algorithm, issuer: String) -> Self {
        Self {
            key,
            validation: Validation {
                leeway: 5,
                validate_exp: true,
                validate_nbf: false,
                iss: Some(issuer),
                algorithms: vec![algorithm],
                ..Default::default()
            },
        }
    }

    pub fn validate(&self, token: &str) -> Option<Token> {
        decode(token, &self.key, &self.validation)
            .map(|v| v.claims)
            .map_err(|e| {
                debug!("Token validation failed: {}", e);
                e
            })
            .ok()
    }
}
