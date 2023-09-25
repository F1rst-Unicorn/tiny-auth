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
use crate::config::Config;
use crate::config::Store;
use crate::http::TokenCertificate;
use crate::runtime::Error;
use crate::store::file::*;
use crate::util::read_file;
use base64::engine::general_purpose;
use base64::engine::general_purpose::STANDARD;
use base64::engine::Engine;
use chrono::Duration;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use log::error;
use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::bn::BigNumRef;
use openssl::ec::EcKey;
use openssl::hash::Hasher;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use std::sync::Arc;
use tera::Tera;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_business::cors::CorsListerImpl;
use tiny_auth_business::issuer_configuration::IssuerConfiguration;
use tiny_auth_business::jwk::Jwk;
use tiny_auth_business::jwk::Jwks;
use tiny_auth_business::rate_limiter::RateLimiter;
use tiny_auth_business::store::memory::*;
use tiny_auth_business::store::*;
use tiny_auth_business::token::TokenCreator;
use tiny_auth_business::token::TokenValidator;

pub struct Constructor<'a> {
    config: &'a Config,

    user_store: Option<Arc<dyn UserStore>>,

    client_store: Option<Arc<dyn ClientStore>>,

    scope_store: Option<Arc<dyn ScopeStore>>,

    tera: Option<Tera>,

    issuer_url: String,

    public_key: String,

    issuer_configuration: IssuerConfiguration,

    encoding_key: EncodingKey,

    algorithm: Algorithm,

    jwk: Jwk,
}

impl<'a> Constructor<'a> {
    pub fn new(config: &'a Config) -> Result<Self, Error> {
        let user_store = Self::build_user_store(config);
        let client_store = Self::build_client_store(config);
        let scope_store = Self::build_scope_store(config);
        let tera = Some(Self::build_template_engine(config)?);
        let issuer_url = Self::build_issuer_url(config);
        let public_key = read_file(&config.crypto.public_key)?;
        let private_key = read_file(&config.crypto.key)?;
        let (encoding_key, algorithm) = Self::build_encoding_key(&private_key)?;
        let issuer_configuration = Self::build_issuer_config(issuer_url.clone(), algorithm);
        let jwk = Self::build_jwk(&public_key, &issuer_url)?;

        Ok(Self {
            config,
            user_store,
            client_store,
            scope_store,
            tera,
            issuer_url,
            public_key,
            issuer_configuration,
            encoding_key,
            algorithm,
            jwk,
        })
    }

    pub fn get_issuer_config(&self) -> IssuerConfiguration {
        self.issuer_configuration.clone()
    }

    fn build_issuer_config(issuer_url: String, algorithm: Algorithm) -> IssuerConfiguration {
        IssuerConfiguration {
            issuer_url,
            algorithm,
        }
    }

    pub fn build_rate_limiter(&self) -> RateLimiter {
        RateLimiter::new(
            self.config.rate_limit.events,
            Duration::seconds(self.config.rate_limit.period_in_seconds),
        )
    }

    pub fn build_authenticator(&self) -> Option<Authenticator> {
        Some(Authenticator::new(
            self.get_user_store()?,
            self.build_rate_limiter(),
            &self.config.crypto.pepper,
        ))
    }

    pub fn get_user_store(&self) -> Option<Arc<dyn UserStore>> {
        self.user_store.clone()
    }

    fn build_user_store(config: &'a Config) -> Option<Arc<dyn UserStore>> {
        match &config.store {
            None => None,
            Some(Store::Config { base }) => Some(Arc::new(FileUserStore::new(base)?)),
        }
    }

    pub fn get_client_store(&self) -> Option<Arc<dyn ClientStore>> {
        self.client_store.clone()
    }

    fn build_client_store(config: &'a Config) -> Option<Arc<dyn ClientStore>> {
        match &config.store {
            None => None,
            Some(Store::Config { base }) => Some(Arc::new(FileClientStore::new(base)?)),
        }
    }

    pub fn get_scope_store(&self) -> Option<Arc<dyn ScopeStore>> {
        self.scope_store.clone()
    }

    fn build_scope_store(config: &'a Config) -> Option<Arc<dyn ScopeStore>> {
        match &config.store {
            None => None,
            Some(Store::Config { base }) => Some(Arc::new(FileScopeStore::new(base)?)),
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

    pub fn get_template_engine(&self) -> Option<Tera> {
        self.tera.clone()
    }

    fn build_template_engine(config: &'a Config) -> Result<Tera, Error> {
        load_template_engine(&config.web.static_files, config.web.path.as_ref().unwrap())
            .map_err(Into::into)
    }

    pub fn get_public_key(&self) -> TokenCertificate {
        TokenCertificate(self.public_key.clone())
    }

    fn build_issuer_url(config: &'a Config) -> String {
        let mut token_issuer = "http".to_string();
        if config.web.tls.is_some() {
            token_issuer += "s";
        }
        token_issuer += "://";
        token_issuer += &config.web.public_host.domain;
        if let Some(port) = &config.web.public_host.port {
            token_issuer += ":";
            token_issuer += port;
        }
        if let Some(path) = &config.web.path {
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

    fn build_encoding_key(private_key: &str) -> Result<(EncodingKey, Algorithm), Error> {
        let bytes = private_key.as_bytes();
        match EncodingKey::from_rsa_pem(bytes) {
            Err(_) => match EncodingKey::from_ec_pem(bytes) {
                Err(e) => {
                    error!("failed to read private token key: {}", e);
                    Err(e.into())
                }
                Ok(key) => Ok((key, Algorithm::ES384)),
            },
            Ok(key) => Ok((key, Algorithm::PS512)),
        }
    }

    pub fn build_token_creator(&self) -> Result<TokenCreator, Error> {
        Ok(TokenCreator::new(
            self.encoding_key.clone(),
            self.issuer_configuration.clone(),
            self.jwk.clone(),
        ))
    }

    pub fn build_token_validator(&self) -> Result<TokenValidator, Error> {
        let key = match DecodingKey::from_rsa_pem(self.public_key.as_bytes()) {
            Err(_) => DecodingKey::from_ec_pem(self.public_key.as_bytes())?,
            Ok(key) => key,
        };

        Ok(TokenValidator::new(
            key,
            self.algorithm,
            self.issuer_url.clone(),
        ))
    }

    // See https://tools.ietf.org/html/rfc7518#section-6
    fn build_jwk(public_key: &str, issuer_url: &str) -> Result<Jwk, Error> {
        let key = public_key.as_bytes();
        let url = issuer_url.to_string() + "/cert";
        let jwk = if let Ok(key) = Rsa::public_key_from_pem_pkcs1(key) {
            let n = Self::encode_bignum(key.n());
            let e = Self::encode_bignum(key.e());

            let mut hasher = Hasher::new(MessageDigest::sha1())?;
            hasher.update(&key.n().to_vec())?;
            hasher.update(&key.e().to_vec())?;
            let id = STANDARD.encode(hasher.finish()?);
            Jwk::new_rsa(id, url, n, e)
        } else if let Ok(key) = Rsa::public_key_from_pem(key) {
            let n = Self::encode_bignum(key.n());
            let e = Self::encode_bignum(key.e());
            let mut hasher = Hasher::new(MessageDigest::sha1())?;
            hasher.update(&key.n().to_vec())?;
            hasher.update(&key.e().to_vec())?;
            let id = STANDARD.encode(hasher.finish()?);
            Jwk::new_rsa(id, url, n, e)
        } else if let Ok(key) = EcKey::public_key_from_pem(key) {
            let crv = match key.group().curve_name() {
                Some(openssl::nid::Nid::SECP384R1) => "P-384".to_string(),
                Some(_) | None => {
                    error!("Unsupported curve in token key");
                    return Err(Error::LoggedBeforeError);
                }
            };

            let mut context = BigNumContext::new()?;
            let mut x = BigNum::new()?;
            let mut y = BigNum::new()?;
            let mut hasher = Hasher::new(MessageDigest::sha1())?;
            hasher.update(&x.to_vec())?;
            hasher.update(&y.to_vec())?;
            hasher.update(crv.as_bytes())?;

            key.public_key()
                .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut context)?;

            let x = Self::encode_bignum(&x);
            let y = Self::encode_bignum(&y);
            let id = STANDARD.encode(hasher.finish()?);
            Jwk::new_ecdsa(id, url, crv, x, y)
        } else {
            error!("Token key has unknown type, tried RSA and ECDSA");
            return Err(Error::LoggedBeforeError);
        };

        Ok(jwk)
    }

    pub fn build_jwks(&self) -> Result<Jwks, Error> {
        Ok(Jwks::with_keys(vec![self.jwk.clone()]))
    }

    pub fn build_cors_lister(&self) -> Result<Arc<dyn CorsLister>, Error> {
        Ok(Arc::new(CorsListerImpl::new(self.config.web.cors.clone())))
    }

    fn encode_bignum(num: &BigNumRef) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(num.to_vec())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use super::super::tera::load_template_engine;
    use tiny_auth_business::authenticator::Authenticator;
    use tiny_auth_business::issuer_configuration::IssuerConfiguration;
    use tiny_auth_business::jwk::Jwk;
    use tiny_auth_business::store::AuthorizationCodeStore;
    use tiny_auth_business::store::ClientStore;
    use tiny_auth_business::store::ScopeStore;
    use tiny_auth_business::store::UserStore;
    use tiny_auth_business::token::TokenCreator;
    use tiny_auth_business::token::TokenValidator;

    use std::sync::Arc;

    use actix_web::web::Data;

    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::EncodingKey;

    use tera::Tera;

    pub fn build_test_token_creator() -> Data<TokenCreator> {
        Data::new(TokenCreator::new(
            build_test_encoding_key(),
            build_test_issuer_config(),
            build_test_jwk(),
        ))
    }

    pub fn build_test_issuer_config_for_web() -> Data<IssuerConfiguration> {
        Data::new(build_test_issuer_config())
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

    pub fn build_test_tera() -> Data<Tera> {
        Data::new(
            load_template_engine(
                &(env!("CARGO_MANIFEST_DIR").to_string() + "/../../static/"),
                "",
            )
            .unwrap(),
        )
    }

    pub fn build_test_client_store() -> Data<Arc<dyn ClientStore>> {
        Data::new(test_fixtures::build_test_client_store())
    }

    pub fn build_test_user_store() -> Data<Arc<dyn UserStore>> {
        Data::new(test_fixtures::build_test_user_store())
    }

    pub fn build_test_scope_store() -> Data<Arc<dyn ScopeStore>> {
        Data::new(test_fixtures::build_test_scope_store())
    }

    pub fn build_test_auth_code_store() -> Data<Arc<dyn AuthorizationCodeStore>> {
        Data::new(test_fixtures::build_test_auth_code_store())
    }

    pub fn build_test_rate_limiter() -> RateLimiter {
        RateLimiter::new(3, Duration::minutes(5))
    }

    pub fn build_test_authenticator() -> Data<Authenticator> {
        Data::new(Authenticator::new(
            test_fixtures::build_test_user_store(),
            build_test_rate_limiter(),
            "pepper",
        ))
    }

    pub fn build_test_decoding_key() -> DecodingKey {
        DecodingKey::from_secret("secret".as_bytes())
    }

    pub fn build_test_token_validator() -> Data<TokenValidator> {
        Data::new(TokenValidator::new(
            build_test_decoding_key(),
            build_test_algorithm(),
            build_test_token_issuer(),
        ))
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
