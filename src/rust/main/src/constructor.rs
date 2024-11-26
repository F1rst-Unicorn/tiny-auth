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

use crate::config::{ClientAttributes, Config, LdapMode, LdapUsageClients};
use crate::config::{LdapUsageUsers, Store};
use crate::config::{TlsVersion, UserAttributes};
use crate::runtime::Error;
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
use openssl::bn::BigNum;
use openssl::bn::BigNumContext;
use openssl::bn::BigNumRef;
use openssl::ec::EcKey;
use openssl::hash::Hasher;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;
use rustls::SupportedProtocolVersion;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tera::Tera;
use tiny_auth_business::authenticator::inject::authenticator;
use tiny_auth_business::authenticator::Authenticator;
use tiny_auth_business::authorize_endpoint::Handler as AuthorizeHandler;
use tiny_auth_business::change_password::Handler as ChangePasswordHandler;
use tiny_auth_business::consent::Handler as ConsentHandler;
use tiny_auth_business::cors::inject::cors_lister;
use tiny_auth_business::cors::CorsLister;
use tiny_auth_business::data::jwk::Jwk;
use tiny_auth_business::data::jwk::Jwks;
use tiny_auth_business::data::password::inject::{
    dispatching_password_store, in_place_password_store,
};
use tiny_auth_business::data::password::DispatchingPasswordStore;
use tiny_auth_business::health::inject::health_check;
use tiny_auth_business::health::{HealthCheck, HealthCheckCommand, HealthChecker};
use tiny_auth_business::issuer_configuration::IssuerConfiguration;
use tiny_auth_business::rate_limiter::RateLimiter;
use tiny_auth_business::store::client_store::MergingClientStore;
use tiny_auth_business::store::memory::*;
use tiny_auth_business::store::user_store::MergingUserStore;
use tiny_auth_business::store::*;
use tiny_auth_business::template::web::{
    AuthenticateContext, ConsentContext, WebTemplater, WebappRootContext,
};
use tiny_auth_business::token::TokenCreator;
use tiny_auth_business::token::TokenValidator;
use tiny_auth_business::userinfo_endpoint;
use tiny_auth_ldap::inject::{
    connector, search_bind_check, simple_bind_check, ClientConfig, UserConfig,
};
use tiny_auth_template::inject::{
    bind_dn_templater, data_loader_templater, ldap_search_templater, scope_templater,
};
use tiny_auth_template::web::load_template_engine;
use tiny_auth_web::cors::CorsChecker;
use tiny_auth_web::endpoints::cert::TokenCertificate;
use tiny_auth_web::endpoints::discovery::Handler as DiscoveryHandler;
use tiny_auth_web::endpoints::token::Handler as TokenHandler;
use tiny_auth_web::endpoints::userinfo::Handler as UserInfoHandler;
use tiny_auth_web::ApiUrl;
use tokio::sync::broadcast::{channel, Sender};
use tracing::{debug, error, span, warn, Level};

pub struct Constructor<'a> {
    config: &'a Config,

    user_store: Arc<dyn UserStore>,

    client_store: Arc<dyn ClientStore>,

    scope_store: Arc<dyn ScopeStore>,

    reload_sender: Sender<ReloadEvent>,

    store_paths: Vec<PathBuf>,

    authorization_code_store: Arc<dyn AuthorizationCodeStore>,

    health_checks: Vec<HealthCheck>,

    tera: Arc<Tera>,

    public_keys: Vec<String>,

    issuer_configuration: IssuerConfiguration,

    encoding_key: EncodingKey,

    jwks: Jwks,

    token_validator: Arc<TokenValidator>,

    own_token_validator: Arc<TokenValidator>,

    authenticator: Arc<Authenticator>,

    tls_cert: Option<String>,

    tls_key: Option<String>,

    client_ca: Option<String>,
}

impl<'a> Constructor<'a> {
    pub async fn new(config: &'a Config) -> Result<Self, Error> {
        let (
            user_store,
            password_store,
            client_store,
            scope_store,
            reload_sender,
            store_paths,
            auth_code_store,
            health_checks,
        ) = Self::build_stores(config).await?;
        let tera = Arc::new(Self::build_template_engine(config)?);
        let issuer_url = Self::build_issuer_url(config);
        let (public_key, public_keys, private_key) = Self::read_token_keypairs(config)?;
        let (encoding_key, algorithm) = Self::build_encoding_key(&private_key)?;
        let issuer_configuration = Self::build_issuer_config(issuer_url.clone(), algorithm);
        let jwks = Jwks::with_keys(
            Self::build_jwk(public_key.as_str(), &issuer_url, 0)?,
            public_keys
                .iter()
                .enumerate()
                .map(|(i, k)| Self::build_jwk(k, &issuer_url, i + 1))
                .try_fold(vec![], |mut v, i| {
                    v.push(i?);
                    Ok::<Vec<Jwk>, Error>(v)
                })?,
        );
        let token_validator: Arc<TokenValidator> = Arc::new(Self::build_token_validator(
            public_key.as_str(),
            algorithm,
            &issuer_url,
        )?);
        let own_token_validator: Arc<TokenValidator> = Arc::new(Self::build_own_token_validator(
            public_key.as_str(),
            algorithm,
            &issuer_url,
        )?);
        let rate_limiter = Self::build_rate_limiter(config);
        let authenticator = Self::build_authenticator(
            user_store.clone(),
            rate_limiter.clone(),
            password_store.clone(),
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
            reload_sender,
            store_paths,
            authorization_code_store: auth_code_store
                .unwrap_or_else(|| Self::build_auth_code_store()),
            health_checks,
            tera,
            public_keys,
            issuer_configuration,
            encoding_key,
            jwks,
            token_validator,
            own_token_validator,
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
        password_store: Arc<DispatchingPasswordStore>,
    ) -> Arc<Authenticator> {
        Arc::new(authenticator(user_store, rate_limiter, password_store))
    }

    #[allow(clippy::type_complexity)]
    async fn build_stores(
        config: &Config,
    ) -> Result<
        (
            Arc<dyn UserStore>,
            Arc<DispatchingPasswordStore>,
            Arc<dyn ClientStore>,
            Arc<dyn ScopeStore>,
            Sender<ReloadEvent>,
            Vec<PathBuf>,
            Option<Arc<dyn AuthorizationCodeStore>>,
            Vec<HealthCheck>,
        ),
        Error,
    > {
        let mut client_stores: Vec<Arc<dyn ClientStore>> = vec![];
        let mut user_stores: Vec<Arc<dyn UserStore>> = vec![];
        let mut scope_stores: Vec<Arc<dyn ScopeStore>> = vec![];
        let mut password_stores: BTreeMap<String, Arc<dyn PasswordStore>> = BTreeMap::default();
        let (sender, _receiver) = channel(8);
        let mut store_paths = Vec::new();
        let mut health_checks = Vec::new();
        let in_place_password_store = Arc::new(in_place_password_store(&config.crypto.pepper));
        let mut auth_code_store: Option<Arc<dyn AuthorizationCodeStore>> = None;

        for store_config in &config.store {
            match store_config {
                Store::Config { name: _, base } => {
                    store_paths.push(base.into());
                    match FileStore::new(Path::new(&base), "clients", sender.subscribe()).await {
                        None => return Err(LoggedBeforeError),
                        Some(v) => client_stores.push(v),
                    };
                    match FileStore::new(Path::new(&base), "users", sender.subscribe()).await {
                        None => return Err(LoggedBeforeError),
                        Some(v) => user_stores.push(v),
                    };
                    match FileStore::new(Path::new(&base), "scopes", sender.subscribe()).await {
                        None => return Err(LoggedBeforeError),
                        Some(v) => scope_stores.push(v),
                    };
                }
                Store::Ldap {
                    name,
                    urls,
                    mode: LdapMode::SimpleBind { bind_dn_format },
                    connect_timeout_in_seconds,
                    starttls,
                } => {
                    let templaters: Vec<_> = bind_dn_format
                        .iter()
                        .map(|v| bind_dn_templater(v))
                        .collect();
                    let name = "ldap ".to_owned() + name;
                    let connector = connector(
                        urls,
                        std::time::Duration::from_secs(*connect_timeout_in_seconds as u64),
                        *starttls,
                    );
                    let check: Arc<dyn HealthCheckCommand> =
                        Arc::new(simple_bind_check(connector.clone()));
                    health_checks.push(health_check(&name, check));
                    password_stores.insert(
                        name.clone(),
                        tiny_auth_ldap::inject::simple_bind_store(
                            name.as_str(),
                            templaters.as_slice(),
                            connector,
                        ),
                    );
                }
                Store::Ldap {
                    name,
                    urls,
                    mode:
                        LdapMode::SearchBind {
                            bind_dn,
                            bind_dn_password,
                            searches,
                            use_for,
                        },
                    connect_timeout_in_seconds,
                    starttls,
                } => {
                    let searches = searches
                        .iter()
                        .map(|v| tiny_auth_ldap::LdapSearch {
                            base_dn: v.base_dn.clone(),
                            search_filter: ldap_search_templater(&v.search_filter),
                        })
                        .collect();

                    let user_config = match &use_for.users {
                        None => None,
                        Some(LdapUsageUsers { attributes: None }) => UserConfig {
                            allowed_scopes_attribute: None,
                        }
                        .into(),
                        Some(LdapUsageUsers {
                            attributes: Some(UserAttributes { allowed_scopes }),
                        }) => UserConfig {
                            allowed_scopes_attribute: allowed_scopes.clone(),
                        }
                        .into(),
                    };

                    let client_config = match &use_for.clients {
                        None => None,
                        Some(LdapUsageClients { attributes: None }) => ClientConfig {
                            client_type_attribute: None,
                            allowed_scopes_attribute: None,
                            password_attribute: None,
                            public_key_attribute: None,
                            redirect_uri_attribute: None,
                        }
                        .into(),
                        Some(LdapUsageClients {
                            attributes:
                                Some(ClientAttributes {
                                    client_type,
                                    redirect_uri,
                                    password,
                                    public_key,
                                    allowed_scopes,
                                }),
                        }) => ClientConfig {
                            client_type_attribute: client_type.clone(),
                            allowed_scopes_attribute: allowed_scopes.clone(),
                            password_attribute: password.clone(),
                            public_key_attribute: public_key.clone(),
                            redirect_uri_attribute: redirect_uri.clone(),
                        }
                        .into(),
                    };

                    let name = "ldap ".to_owned() + name;
                    let connector = connector(
                        urls,
                        std::time::Duration::from_secs(*connect_timeout_in_seconds as u64),
                        *starttls,
                    );
                    let check: Arc<dyn HealthCheckCommand> = Arc::new(search_bind_check(
                        connector.clone(),
                        bind_dn,
                        bind_dn_password,
                    ));

                    let ldap_store = tiny_auth_ldap::inject::search_bind_store(
                        name.as_str(),
                        connector,
                        bind_dn,
                        bind_dn_password,
                        searches,
                        user_config,
                        client_config,
                    );
                    health_checks.push(health_check(&name, check));
                    user_stores.push(ldap_store.clone());
                    client_stores.push(ldap_store.clone());
                    password_stores.insert(name.clone(), ldap_store);
                }
                Store::Sqlite {
                    name,
                    base,
                    use_for,
                } => {
                    let _store_span = span!(Level::INFO, "", store = %name).entered();
                    let templater = data_loader_templater();
                    let user_loaders = tiny_auth_sqlite::inject::data_assembler(
                        use_for.users.iter().flat_map(|v| v.iter()).filter_map(|v| {
                            v.try_into().map_err(|e| warn!(%e, "invalid location")).ok()
                        }),
                        templater.clone(),
                    );
                    let client_loaders = tiny_auth_sqlite::inject::data_assembler(
                        use_for
                            .clients
                            .iter()
                            .flat_map(|v| v.iter())
                            .filter_map(|v| {
                                v.try_into().map_err(|e| warn!(%e, "invalid location")).ok()
                            }),
                        templater.clone(),
                    );

                    let (sqlite_store, check) = match tiny_auth_sqlite::inject::sqlite_store(
                        name.as_str(),
                        &(String::from("sqlite://") + base.to_string_lossy().as_ref()),
                        in_place_password_store.clone(),
                        user_loaders,
                        client_loaders,
                    )
                    .await
                    {
                        Err(e) => {
                            error!(%e, %name, "failed to create sqlite store");
                            return Err(LoggedBeforeError);
                        }
                        Ok(v) => v,
                    };

                    let health_check_name = "sqlite ".to_owned() + name;
                    health_checks.push(health_check(health_check_name.as_str(), Arc::new(check)));
                    if use_for.users.is_some() {
                        user_stores.push(sqlite_store.clone());
                    }
                    if use_for.clients.is_some() {
                        client_stores.push(sqlite_store.clone());
                    }
                    if use_for.scopes {
                        scope_stores.push(sqlite_store.clone());
                    }
                    if use_for.passwords {
                        password_stores.insert(name.clone(), sqlite_store.clone());
                    }
                    if use_for.auth_codes {
                        match auth_code_store {
                            None => auth_code_store = Some(sqlite_store),
                            Some(_) => {
                                error!(%name, "more than one auth code store configured");
                                return Err(LoggedBeforeError);
                            }
                        }
                    }
                }
            }
        }

        let password_store = dispatching_password_store(password_stores, in_place_password_store);

        Ok((
            Arc::new(MergingUserStore::from(user_stores)),
            Arc::new(password_store),
            Arc::new(MergingClientStore::from(client_stores)),
            Arc::new(MergingScopeStore::from(scope_stores)),
            sender,
            store_paths,
            auth_code_store,
            health_checks,
        ))
    }

    pub fn get_client_store(&self) -> Arc<dyn ClientStore> {
        self.client_store.clone()
    }

    pub fn get_scope_store(&self) -> Arc<dyn ScopeStore> {
        self.scope_store.clone()
    }

    pub fn reload_sender(&self) -> Sender<ReloadEvent> {
        self.reload_sender.clone()
    }

    pub fn store_paths(&self) -> Vec<PathBuf> {
        self.store_paths.clone()
    }

    pub fn build_auth_code_store() -> Arc<dyn AuthorizationCodeStore> {
        let result = Arc::new(MemoryAuthorizationCodeStore::default());
        let arg = result.clone();
        tokio::spawn(async {
            auth_code_clean_job(arg).await;
        });
        result
    }

    fn build_template_engine(config: &'a Config) -> Result<Tera, Error> {
        Ok(load_template_engine(
            &config.web.static_files.to_string_lossy(),
            config.web.path.as_deref().unwrap_or(""),
        )?)
    }

    pub fn get_public_keys(&self) -> Vec<TokenCertificate> {
        self.public_keys
            .iter()
            .map(Clone::clone)
            .map(TokenCertificate)
            .collect()
    }

    fn build_issuer_url(config: &'a Config) -> String {
        let mut token_issuer = "http".to_owned();
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

    fn read_token_keypairs(config: &'a Config) -> Result<(String, Vec<String>, String), Error> {
        let first_key = match config.crypto.keys.first() {
            None => {
                error!("at least one crypto.keys entry must be given");
                return Err(LoggedBeforeError);
            }
            Some(v) => v,
        };
        let private_key = read_file(&first_key.key)?;
        let public_key = read_file(&first_key.public_key)?;
        let public_keys = config
            .crypto
            .keys
            .iter()
            .skip(1)
            .map(|k| read_file(&k.public_key))
            .try_fold(vec![], |mut v, i| {
                v.push(i?);
                Ok::<Vec<String>, Error>(v)
            })?;

        Ok((public_key, public_keys, private_key))
    }

    fn build_encoding_key(private_key: &str) -> Result<(EncodingKey, Algorithm), Error> {
        let bytes = private_key.as_bytes();
        match EncodingKey::from_rsa_pem(bytes) {
            Err(e) => {
                debug!(%e, "not an RSA key");
                match EncodingKey::from_ec_pem(bytes) {
                    Err(e) => {
                        error!(%e, "failed to read private token key");
                        Err(e.into())
                    }
                    Ok(key) => Ok((key, Algorithm::ES384)),
                }
            }
            Ok(key) => Ok((key, Algorithm::PS512)),
        }
    }

    pub fn build_token_creator(&self) -> TokenCreator {
        TokenCreator::new(
            self.encoding_key.clone(),
            self.issuer_configuration.clone(),
            self.jwks.first_key.clone(),
            Arc::new(tiny_auth_business::clock::inject::clock()),
            Duration::seconds(self.config.web.token_timeout_in_seconds.unwrap_or_default()),
            Duration::seconds(
                self.config
                    .web
                    .refresh_token_timeout_in_seconds
                    .unwrap_or_default(),
            ),
            scope_templater(),
        )
    }

    pub fn build_token_validator(
        public_key: &str,
        algorithm: Algorithm,
        issuer_url: &str,
    ) -> Result<TokenValidator, Error> {
        let key = match DecodingKey::from_rsa_pem(public_key.as_bytes()) {
            Err(e) => {
                debug!(%e, "not an RSA key");
                DecodingKey::from_ec_pem(public_key.as_bytes())?
            }
            Ok(key) => key,
        };

        Ok(TokenValidator::new(key, algorithm, issuer_url.to_owned()))
    }

    pub fn build_own_token_validator(
        public_key: &str,
        algorithm: Algorithm,
        issuer_url: &str,
    ) -> Result<TokenValidator, Error> {
        let key = match DecodingKey::from_rsa_pem(public_key.as_bytes()) {
            Err(e) => {
                debug!(%e, "not an RSA key");
                DecodingKey::from_ec_pem(public_key.as_bytes())?
            }
            Ok(key) => key,
        };

        Ok(TokenValidator::new_for_own_api(
            key,
            algorithm,
            issuer_url.to_owned(),
        ))
    }

    // See https://tools.ietf.org/html/rfc7518#section-6
    fn build_jwk(
        public_key: &str,
        issuer_url: &str,
        public_key_index: usize,
    ) -> Result<Jwk, Error> {
        let key = public_key.as_bytes();
        let url = format!("{issuer_url}/cert/{public_key_index}").to_owned();
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
                Some(openssl::nid::Nid::SECP384R1) => "P-384".to_owned(),
                Some(_) | None => {
                    error!("unsupported curve in token key");
                    return Err(LoggedBeforeError);
                }
            };

            let mut context = BigNumContext::new()?;
            let mut x = BigNum::new()?;
            let mut y = BigNum::new()?;

            key.public_key()
                .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut context)?;

            let mut hasher = Hasher::new(MessageDigest::sha1())?;
            hasher.update(&x.to_vec())?;
            hasher.update(&y.to_vec())?;
            hasher.update(crv.as_bytes())?;

            let x = Self::encode_bignum(&x);
            let y = Self::encode_bignum(&y);
            let id = STANDARD.encode(hasher.finish()?);
            Jwk::new_ecdsa(id, url, crv, x, y)
        } else {
            error!("token key has unknown type, tried RSA and ECDSA");
            return Err(LoggedBeforeError);
        };

        Ok(jwk)
    }

    pub fn build_jwks(&self) -> Jwks {
        self.jwks.clone()
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
        self.config.api.bind.as_str()
    }

    fn path(&self) -> &'a str {
        self.config.api.path.as_deref().unwrap_or_default()
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

    fn change_password_handler(&self) -> ChangePasswordHandler {
        ChangePasswordHandler::new(self.authenticator.clone(), self.own_token_validator.clone())
    }
}

impl<'a> tiny_auth_web::Constructor<'a> for Constructor<'a> {
    fn get_public_keys(&self) -> Vec<TokenCertificate> {
        self.get_public_keys()
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
        Arc::new(cors_lister(self.config.web.cors.clone()))
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

    fn shutdown_timeout(&self) -> u64 {
        self.config.web.shutdown_timeout
    }

    fn tls_enabled(&self) -> bool {
        self.config.web.tls.is_some()
    }

    fn web_path(&self) -> String {
        self.config.web.path.clone().unwrap_or_default()
    }

    fn static_files(&self) -> PathBuf {
        self.config.web.static_files.clone()
    }

    fn session_timeout(&self) -> i64 {
        self.config
            .web
            .session_timeout_in_seconds
            .unwrap_or_default()
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

    fn authorize_handler(&self) -> Arc<AuthorizeHandler> {
        Arc::new(tiny_auth_business::authorize_endpoint::inject::handler(
            self.client_store.clone(),
        ))
    }

    fn consent_handler(&self) -> Arc<ConsentHandler> {
        Arc::new(tiny_auth_business::consent::inject::handler(
            self.scope_store.clone(),
            self.user_store.clone(),
            self.client_store.clone(),
            self.authorization_code_store.clone(),
            self.build_token_creator(),
        ))
    }

    fn token_handler(&self) -> Arc<TokenHandler> {
        Arc::new(tiny_auth_web::endpoints::token::Handler::new(
            Arc::new(tiny_auth_business::token_endpoint::inject::handler(
                self.client_store.clone(),
                self.user_store.clone(),
                self.authorization_code_store.clone(),
                self.build_token_creator(),
                self.authenticator.clone(),
                self.token_validator.clone(),
                self.scope_store.clone(),
                self.issuer_configuration.clone(),
            )),
            Arc::new(CorsChecker::new(self.build_cors_lister())),
        ))
    }

    fn user_info_handler(&self) -> Arc<UserInfoHandler> {
        Arc::new(tiny_auth_web::endpoints::userinfo::inject::handler(
            Arc::new(userinfo_endpoint::inject::handler(
                self.token_validator.clone(),
                self.build_token_creator(),
                self.client_store.clone(),
                self.user_store.clone(),
                self.scope_store.clone(),
            )),
            Arc::new(CorsChecker::new(self.build_cors_lister())),
        ))
    }

    fn discovery_handler(&self) -> Arc<DiscoveryHandler> {
        Arc::new(tiny_auth_web::endpoints::discovery::inject::handler(
            self.build_cors_lister(),
            self.issuer_configuration.clone(),
            self.scope_store.clone(),
        ))
    }

    fn api_url(&self) -> ApiUrl {
        ApiUrl(
            if self.config.web.tls.is_some() {
                "https://"
            } else {
                "http://"
            }
            .to_owned()
                + &self.config.api.public_host.domain
                + &self
                    .config
                    .api
                    .public_host
                    .port
                    .as_ref()
                    .map(|v| ":".to_owned() + v)
                    .unwrap_or("".to_owned())
                + self.config.api.public_path.as_deref().unwrap_or_default(),
        )
    }

    fn health_checker(&self) -> Arc<HealthChecker> {
        Arc::new(HealthChecker(self.health_checks.clone()))
    }

    fn webapp_template(&self) -> Arc<dyn for<'b> WebTemplater<WebappRootContext<'b>>> {
        tiny_auth_template::inject::webapp_templater(self.tera.clone())
    }

    fn authorize_template(&self) -> Arc<dyn WebTemplater<()>> {
        tiny_auth_template::inject::authorize_templater(self.tera.clone())
    }

    fn authenticate_template(&self) -> Arc<dyn WebTemplater<AuthenticateContext>> {
        tiny_auth_template::inject::authenticate_templater(self.tera.clone())
    }

    fn consent_template(&self) -> Arc<dyn WebTemplater<ConsentContext>> {
        tiny_auth_template::inject::consent_templater(self.tera.clone())
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
    use tiny_auth_business::data::jwk::Jwk;
    use tiny_auth_business::issuer_configuration::IssuerConfiguration;
    use tiny_auth_business::store::AuthorizationCodeStore;
    use tiny_auth_business::store::ScopeStore;
    use tiny_auth_business::token::TokenValidator;

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
        "https://localhost:8088".to_owned()
    }

    fn build_test_algorithm() -> Algorithm {
        Algorithm::HS256
    }

    pub fn build_test_tera() -> Data<Tera> {
        Data::new(
            load_template_engine(
                &(env!("CARGO_MANIFEST_DIR").to_owned() + "/../../static/"),
                "",
            )
            .unwrap(),
        )
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
            "key_id".to_owned(),
            "".to_owned(),
            "".to_owned(),
            "".to_owned(),
        )
    }
}
