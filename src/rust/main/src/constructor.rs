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

use crate::config::Config;
use crate::config::Store;
use crate::config::TlsVersion;
use crate::runtime::Error;
use crate::runtime::Error::ConfigError;
use crate::runtime::Error::LoggedBeforeError;
use crate::store::file::*;
use crate::util::read_file;
use actix_web::cookie::SameSite;
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
use rustls::SupportedProtocolVersion;
use std::sync::Arc;
use tera::Tera;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::change_password::Handler;
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
use tiny_auth_web::endpoints::cert::TokenCertificate;
use tiny_auth_web::tera::load_template_engine;

pub struct Constructor<'a> {
    config: &'a Config,

    user_store: Arc<dyn UserStore>,

    client_store: Option<Arc<dyn ClientStore>>,

    scope_store: Option<Arc<dyn ScopeStore>>,

    tera: Option<Tera>,

    public_key: String,

    issuer_configuration: IssuerConfiguration,

    encoding_key: EncodingKey,

    jwk: Jwk,

    token_validator: Arc<TokenValidator>,

    authenticator: Arc<Authenticator>,

    tls_cert: Option<String>,

    tls_key: Option<String>,

    client_ca: Option<String>,
}

impl<'a> Constructor<'a> {
    pub fn new(config: &'a Config) -> Result<Self, Error> {
        let user_store = Self::build_user_store(config)?;
        let client_store = Self::build_client_store(config);
        let scope_store = Self::build_scope_store(config);
        let tera = Some(Self::build_template_engine(config)?);
        let issuer_url = Self::build_issuer_url(config);
        let public_key = read_file(&config.crypto.public_key)?;
        let private_key = read_file(&config.crypto.key)?;
        let (encoding_key, algorithm) = Self::build_encoding_key(&private_key)?;
        let issuer_configuration = Self::build_issuer_config(issuer_url.clone(), algorithm);
        let jwk = Self::build_jwk(&public_key, &issuer_url)?;
        let token_validator = Arc::new(Self::build_token_validator(
            &public_key,
            algorithm,
            &issuer_url,
        )?);
        let rate_limiter = Self::build_rate_limiter(config);
        let authenticator = Self::build_authenticator(
            user_store.clone(),
            rate_limiter.clone(),
            &config.crypto.pepper,
        );
        let (tls_cert, tls_key, client_ca) = match &config.web.tls {
            None => (None, None, None),
            Some(tls) => (
                Some(read_file(&tls.certificate)?),
                Some(read_file(&tls.key)?),
                match tls.client_ca.as_ref().map(read_file) {
                    None => None,
                    Some(v) => Some(v?),
                },
            ),
        };

        Ok(Self {
            config,
            user_store,
            client_store,
            scope_store,
            tera,
            public_key,
            issuer_configuration,
            encoding_key,
            jwk,
            token_validator,
            authenticator,
            tls_cert,
            tls_key,
            client_ca,
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

    pub fn build_rate_limiter(config: &Config) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(
            config.rate_limit.events,
            Duration::seconds(config.rate_limit.period_in_seconds),
        ))
    }

    pub fn build_authenticator(
        user_store: Arc<dyn UserStore>,
        rate_limiter: Arc<RateLimiter>,
        pepper: &str,
    ) -> Arc<Authenticator> {
        Arc::new(Authenticator::new(user_store, rate_limiter, pepper))
    }

    fn build_user_store(config: &'a Config) -> Result<Arc<dyn UserStore>, Error> {
        match &config.store {
            None => Err(ConfigError("no user store configured".to_string())),
            Some(Store::Config { base }) => {
                Ok(Arc::new(FileUserStore::new(base).ok_or(LoggedBeforeError)?))
            }
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
        Ok(load_template_engine(
            &config.web.static_files,
            config.web.path.as_ref().unwrap(),
        )?)
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

    pub fn build_token_creator(&self) -> TokenCreator {
        TokenCreator::new(
            self.encoding_key.clone(),
            self.issuer_configuration.clone(),
            self.jwk.clone(),
            Arc::new(tiny_auth_business::clock::inject::clock()),
            Duration::seconds(
                self.config
                    .web
                    .token_timeout_in_seconds
                    .expect("no default given"),
            ),
            Duration::seconds(
                self.config
                    .web
                    .refresh_token_timeout_in_seconds
                    .expect("no default given"),
            ),
        )
    }

    pub fn build_token_validator(
        public_key: &str,
        algorithm: Algorithm,
        issuer_url: &str,
    ) -> Result<TokenValidator, Error> {
        let key = match DecodingKey::from_rsa_pem(public_key.as_bytes()) {
            Err(_) => DecodingKey::from_ec_pem(public_key.as_bytes())?,
            Ok(key) => key,
        };

        Ok(TokenValidator::new(key, algorithm, issuer_url.to_string()))
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

    pub fn build_jwks(&self) -> Jwks {
        Jwks::with_keys(vec![self.jwk.clone()])
    }

    pub fn build_cors_lister(&self) -> Arc<dyn CorsLister> {
        Arc::new(CorsListerImpl::new(self.config.web.cors.clone()))
    }

    fn encode_bignum(num: &BigNumRef) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(num.to_vec())
    }

    pub fn user_store(&self) -> Arc<dyn UserStore> {
        self.user_store.clone()
    }
}

impl<'a> tiny_auth_api::Constructor<'a> for Constructor<'a> {
    fn endpoint(&self) -> &'a str {
        self.config.api.endpoint.as_str()
    }

    fn tls_key(&self) -> Option<String> {
        self.tls_key.clone()
    }

    fn tls_cert(&self) -> Option<String> {
        self.tls_cert.clone()
    }

    fn tls_client_ca(&self) -> Option<String> {
        self.client_ca.clone()
    }

    fn change_password_handler(&self) -> Handler {
        Handler::new(self.authenticator.clone(), self.token_validator.clone())
    }
}

impl<'a> tiny_auth_web::Constructor<'a> for Constructor<'a> {
    fn get_template_engine(&self) -> Option<Tera> {
        self.get_template_engine()
    }
    fn get_public_key(&self) -> TokenCertificate {
        self.get_public_key()
    }
    fn build_token_creator(&self) -> TokenCreator {
        self.build_token_creator()
    }
    fn token_validator(&self) -> Arc<TokenValidator> {
        self.token_validator.clone()
    }
    fn user_store(&self) -> Arc<dyn UserStore> {
        self.user_store.clone()
    }
    fn get_client_store(&self) -> Option<Arc<dyn ClientStore>> {
        self.get_client_store()
    }
    fn get_scope_store(&self) -> Option<Arc<dyn ScopeStore>> {
        self.get_scope_store()
    }
    fn build_auth_code_store(&self) -> Option<Arc<dyn AuthorizationCodeStore>> {
        self.build_auth_code_store()
    }
    fn authenticator(&self) -> Arc<Authenticator> {
        self.authenticator.clone()
    }
    fn get_issuer_config(&self) -> IssuerConfiguration {
        self.get_issuer_config()
    }
    fn build_jwks(&self) -> Jwks {
        self.build_jwks()
    }
    fn build_cors_lister(&self) -> Arc<dyn CorsLister> {
        self.build_cors_lister()
    }

    fn tls_key(&self) -> Option<String> {
        self.tls_key.clone()
    }

    fn tls_cert(&self) -> Option<String> {
        self.tls_cert.clone()
    }

    fn tls_client_ca(&self) -> Option<String> {
        self.client_ca.clone()
    }

    fn tls_versions(&self) -> Vec<&'static SupportedProtocolVersion> {
        self.config
            .web
            .tls
            .as_ref()
            .map(|v| {
                v.versions
                    .clone()
                    .into_iter()
                    .map(TlsVersion::into)
                    .collect::<Vec<&SupportedProtocolVersion>>()
            })
            .unwrap_or_default()
    }

    fn bind(&self) -> String {
        self.config.web.bind.clone()
    }

    fn workers(&self) -> Option<usize> {
        self.config.web.workers
    }

    fn tls_enabled(&self) -> bool {
        self.config.web.tls.is_some()
    }

    fn web_path(&self) -> String {
        self.config.web.path.clone().expect("no default given")
    }

    fn static_files(&self) -> String {
        self.config.web.static_files.clone()
    }

    fn session_timeout(&self) -> i64 {
        self.config
            .web
            .session_timeout_in_seconds
            .expect("no default given")
    }

    fn session_same_site_policy(&self) -> SameSite {
        self.config.web.session_same_site_policy.into()
    }

    fn public_domain(&self) -> String {
        self.config.web.public_host.domain.clone()
    }

    fn secret_key(&self) -> String {
        self.config.web.secret_key.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use actix_web::web::Data;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use std::sync::Arc;
    use tera::Tera;
    use tiny_auth_business::authenticator::Authenticator;
    use tiny_auth_business::issuer_configuration::IssuerConfiguration;
    use tiny_auth_business::jwk::Jwk;
    use tiny_auth_business::store::AuthorizationCodeStore;
    use tiny_auth_business::store::ClientStore;
    use tiny_auth_business::store::ScopeStore;
    use tiny_auth_business::store::UserStore;
    use tiny_auth_business::token::TokenValidator;
    use tiny_auth_web::tera::load_template_engine;

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
            Arc::new(build_test_rate_limiter()),
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
