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
use crate::business::token::TokenValidator;
use crate::config::Config;
use crate::config::Store;
use crate::domain::IssuerConfiguration;
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

    pub fn build_issuer_config(&self) -> Option<IssuerConfiguration> {
        Some(IssuerConfiguration {
            issuer_url: self.build_token_issuer(),
            algorithm: self.build_token_creator().ok()?.get_key_type(),
        })
    }

    pub fn build_authenticator(&self) -> Option<Authenticator> {
        Some(Authenticator::new(
            self.build_user_store()?,
            &self.config.crypto.pepper,
        ))
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
        let result = Arc::new(MemoryAuthorizationCodeStore::default());
        let arg = result.clone();
        tokio::spawn(async {
            auth_code_clean_job(arg).await;
        });
        Some(result)
    }

    pub fn build_template_engine(&self) -> Result<Tera, Error> {
        load_template_engine(
            &self.config.web.static_files,
            self.config.web.path.as_ref().unwrap(),
        )
        .map_err(Into::into)
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

    fn build_token_issuer(&self) -> String {
        let mut token_issuer = "http".to_string();
        if self.config.web.tls.is_some() {
            token_issuer += "s";
        }
        token_issuer += "://";
        token_issuer += &self.config.web.domain;
        if let Some(path) = &self.config.web.path {
            if !path.is_empty() {
                if !path.starts_with('/') {
                    token_issuer += "/";
                }
                token_issuer += path;
            }
        }

        while token_issuer.ends_with('/') {
            token_issuer.pop();
        }

        token_issuer
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
        let token_issuer = self.build_token_issuer();
        Ok(TokenCreator::new(encoding_key, algorithm, token_issuer))
    }

    pub fn build_token_validator(&self) -> Result<TokenValidator, Error> {
        let public_key = self.build_public_key()?;

        let family;
        let key = match DecodingKey::from_rsa_pem(public_key.as_bytes()) {
            Err(_) => {
                family = Algorithm::ES384;
                DecodingKey::from_ec_pem(public_key.as_bytes())?
            }
            Ok(key) => {
                family = Algorithm::PS512;
                key
            }
        };

        Ok(TokenValidator::new(
            key.into_static(),
            family,
            self.build_token_issuer(),
        ))
    }
}

#[cfg(test)]
pub mod tests {
    use super::super::tera::load_template_engine;
    use crate::business::authenticator::Authenticator;
    use crate::business::token::TokenCreator;
    use crate::business::token::TokenValidator;
    use crate::store::AuthorizationCodeStore;
    use crate::store::ClientStore;
    use crate::store::UserStore;

    use std::sync::Arc;

    use actix_web::web::Data;

    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::EncodingKey;

    use tera::Tera;

    pub fn build_test_token_creator() -> Data<TokenCreator> {
        Data::new(TokenCreator::new(
            build_test_encoding_key(),
            build_test_algorithm(),
            build_test_token_issuer(),
        ))
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

    pub fn build_test_tera() -> Data<Tera> {
        Data::new(
            load_template_engine(&(env!("CARGO_MANIFEST_DIR").to_string() + "/static/"), "")
                .unwrap(),
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
            "pepper",
        ))
    }

    pub fn build_test_decoding_key() -> DecodingKey<'static> {
        DecodingKey::from_secret("secret".as_bytes()).into_static()
    }

    pub fn build_test_token_validator() -> Data<TokenValidator> {
        Data::new(TokenValidator::new(
            build_test_decoding_key(),
            Algorithm::HS256,
            build_test_token_issuer(),
        ))
    }
}
