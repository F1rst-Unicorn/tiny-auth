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

use super::tera::load_template_engine;
use crate::business::authenticator::Authenticator;
use crate::business::token::TokenCreator;
use crate::config::Config;
use crate::config::Store;
use crate::runtime::Error;
use crate::store::file::*;
use crate::store::memory::*;
use crate::store::*;
use crate::util::read_file;

use std::sync::Arc;

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;

use log::error;

use tera::Tera;

pub struct Constructor<'a> {
    config: &'a Config,
}

impl<'a> Constructor<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn build_authenticator(&self) -> Option<Authenticator> {
        Some(Authenticator::new(self.build_user_store()?))
    }

    pub fn build_user_store(&self) -> Option<Arc<dyn UserStore>> {
        match &self.config.store {
            None => None,
            Some(Store::Config { base }) => Some(Arc::new(FileUserStore::new(&base)?)),
        }
    }

    pub fn build_client_store(&self) -> Option<Arc<dyn ClientStore>> {
        match &self.config.store {
            None => None,
            Some(Store::Config { base }) => Some(Arc::new(FileClientStore::new(&base)?)),
        }
    }

    pub fn build_auth_code_store(&self) -> Option<Arc<dyn AuthorizationCodeStore>> {
        Some(Arc::new(MemoryAuthorizationCodeStore {}))
    }

    pub fn build_template_engine(&self) -> Result<Tera, Error> {
        load_template_engine(&self.config.web.static_files).map_err(Into::into)
    }

    pub fn build_public_key(&self) -> Result<String, Error> {
        let token_certificate = read_file(&self.config.crypto.public_key)?;
        let bytes = token_certificate.as_bytes();
        match DecodingKey::from_rsa_pem(bytes) {
            Err(_) => match DecodingKey::from_ec_pem(bytes) {
                Err(e) => {
                    error!("failed to read public token key: {}", e);
                    Err(e.into())
                }
                Ok(_) => Ok(token_certificate),
            },
            Ok(_) => Ok(token_certificate),
        }
    }

    pub fn build_token_creator(&self) -> Result<TokenCreator, Error> {
        let file = read_file(&self.config.crypto.key)?;
        let bytes = file.as_bytes();
        let mut encoding_key_result = EncodingKey::from_rsa_pem(bytes);
        let algorithm = if encoding_key_result.is_err() {
            encoding_key_result = EncodingKey::from_ec_pem(bytes);
            if let Err(e) = encoding_key_result {
                error!("failed to read private token key: {}", e);
                return Err(e.into());
            }
            Algorithm::ES384
        } else {
            Algorithm::PS512
        };

        let encoding_key = encoding_key_result.unwrap();
        let mut token_issuer = self.config.web.bind.to_string();
        if let Some(path) = &self.config.web.path {
            if !path.is_empty() {
                if !path.starts_with('/') {
                    token_issuer += "/";
                }
                token_issuer += path;
            }
        }
        Ok(TokenCreator::new(encoding_key, algorithm, token_issuer))
    }
}

#[cfg(test)]
pub mod tests {
    use super::super::tera::load_template_engine;
    use crate::business::authenticator::Authenticator;
    use crate::business::token::TokenCreator;
    use crate::store::AuthorizationCodeStore;
    use crate::store::ClientStore;
    use crate::store::UserStore;

    use std::sync::Arc;

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
        Data::new(
            load_template_engine(&(env!("CARGO_MANIFEST_DIR").to_string() + "/static/")).unwrap(),
        )
    }

    pub fn build_test_client_store() -> Data<Arc<dyn ClientStore>> {
        Data::new(crate::store::tests::build_test_client_store())
    }

    pub fn build_test_user_store() -> Data<Arc<dyn UserStore>> {
        Data::new(crate::store::tests::build_test_user_store())
    }

    pub fn build_test_auth_code_store() -> Data<Arc<dyn AuthorizationCodeStore>> {
        Data::new(crate::store::tests::build_test_auth_code_store())
    }

    pub fn build_test_authenticator() -> Data<Authenticator> {
        Data::new(Authenticator::new(
            crate::store::tests::build_test_user_store(),
        ))
    }
}
