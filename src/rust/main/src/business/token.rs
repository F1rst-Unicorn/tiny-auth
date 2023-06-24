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

use crate::domain::IssuerConfiguration;
use crate::domain::Jwk;
use crate::domain::RefreshToken;
use crate::domain::Token;

use jsonwebtoken::decode;
use jsonwebtoken::encode;
use jsonwebtoken::errors::Result;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::Validation;

use serde::de::DeserializeOwned;

use log::debug;

#[derive(Clone)]
pub struct TokenCreator {
    key: EncodingKey,

    issuer: IssuerConfiguration,

    jwk: Jwk,
}

impl TokenCreator {
    pub fn new(key: EncodingKey, issuer: IssuerConfiguration, jwk: Jwk) -> Self {
        Self { key, issuer, jwk }
    }

    pub fn create(&self, mut token: Token) -> Result<String> {
        token.set_issuer(&self.issuer.issuer_url);
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        encode(&header, &token, &self.key)
    }

    pub fn create_refresh_token(&self, mut token: RefreshToken) -> Result<String> {
        token.set_issuer(&self.issuer.issuer_url);
        let mut header = Header::new(self.issuer.algorithm);
        header.kid = Some(self.jwk.key_id.clone());
        header.jku = Some(self.issuer.jwks());
        encode(&header, &token, &self.key)
    }
}

#[derive(Clone)]
pub struct TokenValidator {
    key: DecodingKey,

    validation: Validation,
}

impl TokenValidator {
    pub fn new(key: DecodingKey, algorithm: Algorithm, issuer: String) -> Self {
        let mut validation = jsonwebtoken::Validation::new(algorithm);
        validation.leeway = 5;
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.set_issuer(&[issuer]);
        Self { key, validation }
    }

    pub fn validate<T: DeserializeOwned>(&self, token: &str) -> Option<T> {
        decode::<T>(token, &self.key, &self.validation)
            .map(|v| v.claims)
            .map_err(|e| {
                debug!("Token validation failed: {}", e);
                e
            })
            .ok()
    }
}
