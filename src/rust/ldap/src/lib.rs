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

mod user_lookup;

use crate::user_lookup::UserLookup;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use futures::future::OptionFuture;
use ldap3::{drive, ldap_escape, Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use log::{debug, error, warn};
use std::sync::Arc;
use std::time::Duration;
use tera::{Context, Tera};
use thiserror::Error;
use tiny_auth_business::password::{Error, Password};
use tiny_auth_business::store::{PasswordStore, UserStore};
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;
use url::Url;

type DistinguishedName = String;
type CacheEntry = (DistinguishedName, User);

pub struct LdapStore {
    name: String,
    connector: Connector,
    authenticator: AuthenticatorDispatcher,
    user_lookup: Option<UserLookup>,
}

#[derive(Error, Debug)]
enum LdapError {
    #[error("LDAP connecting failed")]
    ConnectError,
    #[error("search formatting failed: {0}")]
    FormatError(tera::Error),
    #[error("LDAP binding failed")]
    BindError,
    #[error("LDAP binding failed: {0}")]
    BindErrorWithContext(ldap3::LdapError),
}

pub struct Connector {
    urls: Vec<Url>,
    connect_timeout: Duration,
    starttls: bool,
}

impl Connector {
    async fn connect(&self) -> Result<Ldap, LdapError> {
        for url in &self.urls {
            let settings = LdapConnSettings::new()
                .set_conn_timeout(self.connect_timeout)
                .set_starttls(self.starttls);
            debug!("connecting to {}", &url);
            match LdapConnAsync::from_url_with_settings(settings, url).await {
                Err(e) => {
                    warn!("ldap connection to '{}' failed: {}", url, e);
                }
                Ok((conn, ldap)) => {
                    drive!(conn);
                    debug!("connected to {}", &url);
                    return Ok(ldap);
                }
            }
        }
        warn!("failed to connect to any backend");
        Err(LdapError::ConnectError)
    }
}

#[async_trait]
impl UserStore for LdapStore {
    async fn get(&self, username: &str) -> Result<User, UserError> {
        let username = ldap_escape(username).into_owned();
        let user_lookup = self.user_lookup.as_ref().ok_or(UserError::NotFound)?;
        if let UserRepresentation::CachedUser(cached_user) = user_lookup.get_cached(&username).await
        {
            return Ok(cached_user.1);
        }

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let search_entry = self
            .authenticator
            .get_ldap_record(&mut ldap, &username)
            .await?;
        let user = user_lookup.map_to_user(&username, search_entry).await;
        Ok(user)
    }
}

#[async_trait]
impl PasswordStore for LdapStore {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error> {
        let username = ldap_escape(username).into_owned();
        match stored_password {
            Password::Ldap { name } => {
                if name != &self.name {
                    error!(
                        "Password store dispatch bug. Password names {} but this is {}",
                        name, self.name
                    );
                    return Err(Error::BackendError);
                }
            }
            _ => {
                error!("Password store dispatch bug");
            }
        }

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let user = OptionFuture::from(self.user_lookup.as_ref().map(|v| v.get_cached(&username)))
            .await
            .unwrap_or(UserRepresentation::Name(&username));
        self.authenticator
            .authenticate(&mut ldap, user, password_to_check)
            .await
    }
}

#[enum_dispatch(Authenticator)]
enum AuthenticatorDispatcher {
    SimpleBind,
    SearchBind,
}

#[async_trait]
#[enum_dispatch]
trait Authenticator {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, Error>;

    async fn get_ldap_record(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<SearchEntry, UserError>;
}

pub(crate) enum UserRepresentation<'a> {
    Name(&'a str),
    CachedUser(CacheEntry),
}

struct SimpleBind {
    bind_dn_format: Vec<String>,
}

#[async_trait]
impl Authenticator for SimpleBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, Error> {
        match user {
            UserRepresentation::Name(username) => {
                for bind_template in &self.bind_dn_format {
                    let bind_dn = format_username(bind_template, username).map_err(wrap_err)?;
                    if simple_bind(ldap, &bind_dn, password)
                        .await
                        .map_err(wrap_err)?
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            UserRepresentation::CachedUser((dn, _)) => {
                Ok(simple_bind(ldap, &dn, password).await.map_err(wrap_err)?)
            }
        }
    }

    async fn get_ldap_record(&self, _: &mut Ldap, _: &str) -> Result<SearchEntry, UserError> {
        Err(UserError::NotFound)
    }
}

struct SearchBind {
    bind_dn: String,
    bind_dn_password: String,
    searches: Vec<LdapSearch>,
}

pub struct LdapSearch {
    pub base_dn: String,
    pub search_filter: String,
}

trait AttributeMapping<T>: Sync + Send {
    fn map(&self, entity: T, search_entry: &SearchEntry) -> T;
}

#[async_trait]
impl Authenticator for SearchBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, Error> {
        let dn = match user {
            UserRepresentation::Name(username) => {
                let search_entry = self
                    .get_ldap_record(ldap, username)
                    .await
                    .map_err(wrap_err)?;
                search_entry.dn
            }
            UserRepresentation::CachedUser((dn, _)) => dn,
        };
        Ok(simple_bind(ldap, &dn, password).await.map_err(wrap_err)?)
    }

    async fn get_ldap_record(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<SearchEntry, UserError> {
        if !simple_bind(ldap, &self.bind_dn, &self.bind_dn_password)
            .await
            .map_err(wrap_err)?
        {
            warn!(
                "wrong username or password for search bind mode. Username '{}'",
                self.bind_dn
            );
            return Err(UserError::BackendError);
        };

        for search in &self.searches {
            let filter = format_username(&search.search_filter, username).map_err(wrap_err)?;
            debug!("searching in {} for {}", &search.base_dn, &filter);
            let result = match ldap
                .search(&search.base_dn, Scope::Subtree, &filter, &["*", "+"])
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("searching for user '{}' failed. {}", username, e);
                    return Err(UserError::BackendErrorWithContext(Arc::new(e)));
                }
            };

            if let Some(entry) = result.0.into_iter().next() {
                let entry = SearchEntry::construct(entry);
                return Ok(entry);
            }
        }
        Err(UserError::NotFound)
    }
}

async fn simple_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> Result<bool, LdapError> {
    debug!("binding to LDAP as '{}'", bind_dn);
    let result = ldap
        .simple_bind(bind_dn, password)
        .await
        .map_err(LdapError::BindErrorWithContext)?;
    match result.rc {
        0 => Ok(true),
        49 => {
            debug!("wrong username or password");
            Ok(false)
        }
        v => {
            warn!(
                "Unexpected LDAP result code while binding: {}. {}",
                v, result.text
            );
            Err(LdapError::BindError)
        }
    }
}

fn format_username(format: &str, username: &str) -> Result<String, LdapError> {
    let mut tera = Tera::default();
    let mut context = Context::new();
    context.insert("user", username);
    tera.render_str(format, &context).map_err(|e| {
        warn!("failed to construct bind dn: {}", e);
        LdapError::FormatError(e)
    })
}

pub mod inject {
    use crate::user_lookup::{UserAllowedScopesMapping, UserLookup};
    use crate::{AttributeMapping, Connector, LdapSearch, LdapStore, SearchBind, SimpleBind};
    use moka::future::Cache;
    use moka::policy::EvictionPolicy;
    use std::sync::Arc;
    use std::time::Duration;
    use tiny_auth_business::store::PasswordStore;
    use tiny_auth_business::user::User;
    use url::Url;

    pub fn connector(urls: &[Url], connect_timeout: Duration, starttls: bool) -> Connector {
        Connector {
            urls: urls.iter().map(Clone::clone).collect(),
            connect_timeout,
            starttls,
        }
    }

    pub fn simple_bind_store(
        name: &str,
        bind_dn_format: &[String],
        connector: Connector,
    ) -> Arc<dyn PasswordStore> {
        Arc::new(LdapStore {
            name: name.to_string(),
            connector,
            authenticator: SimpleBind {
                bind_dn_format: bind_dn_format.to_vec(),
            }
            .into(),
            user_lookup: None,
        })
    }

    pub struct UserConfig {
        pub allowed_scopes_attribute: Option<String>,
    }

    pub fn search_bind_store(
        name: &str,
        connector: Connector,
        bind_dn: &str,
        bind_dn_password: &str,
        searches: Vec<LdapSearch>,
        user_config: Option<UserConfig>,
    ) -> Arc<LdapStore> {
        Arc::new(LdapStore {
            name: name.to_string(),
            connector,
            authenticator: SearchBind {
                bind_dn: bind_dn.to_string(),
                bind_dn_password: bind_dn_password.to_string(),
                searches,
            }
            .into(),
            user_lookup: user_config.map(|user_config| UserLookup {
                ldap_name: name.to_string(),
                cache: cache(name),
                mappings: user_config
                    .allowed_scopes_attribute
                    .map(|allowed_scopes_attribute| {
                        Arc::new(UserAllowedScopesMapping {
                            attribute: allowed_scopes_attribute,
                        }) as Arc<dyn AttributeMapping<User>>
                    })
                    .into_iter()
                    .collect(),
            }),
        })
    }

    fn cache(name: &str) -> Cache<String, (String, User)> {
        Cache::builder()
            .name(format!("tiny-auth ldap store {name}").as_str())
            .eviction_policy(EvictionPolicy::tiny_lfu())
            .time_to_idle(Duration::from_secs(10))
            .build()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::inject::{connector, UserConfig};
    use pretty_assertions::assert_eq;
    use rstest::fixture;
    use rstest::rstest;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::time::Duration;
    use test_log::test;
    use testcontainers::clients::Cli;
    use testcontainers::core::WaitFor;
    use testcontainers::GenericImage;
    use tiny_auth_business::password::{Error, Password};
    use tiny_auth_business::store::PasswordStore;
    use url::Url;

    #[rstest]
    #[test(tokio::test)]
    pub async fn successful_authentication_works(
        image: GenericImage,
        name: String,
        password: Password,
    ) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = simple_bind_uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "password").await;

        assert_eq!(true, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn failing_authentication_works(
        image: GenericImage,
        name: String,
        password: Password,
    ) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = simple_bind_uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "wrong").await;

        assert_eq!(false, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn successful_search_authentication_works(
        image: GenericImage,
        name: String,
        password: Password,
    ) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = search_bind_uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "password").await;

        assert_eq!(true, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn failing_search_authentication_works(
        image: GenericImage,
        name: String,
        password: Password,
    ) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = search_bind_uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "wrong").await;

        assert_eq!(false, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn successful_search_anonymous_authentication_works(
        image: GenericImage,
        name: String,
        password: Password,
    ) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = search_bind_anonymous_uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "password").await;

        assert_eq!(true, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn failing_search_anonymous_authentication_works(
        image: GenericImage,
        name: String,
        password: Password,
    ) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = search_bind_anonymous_uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "wrong").await;

        assert_eq!(false, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn getting_user_works(image: GenericImage, name: String) {
        let cli = Cli::default();
        let container = cli.run(image);
        let uut = search_bind_uut(name, container.get_host_port_ipv4(1389));
        let input = "user01";

        let actual = uut.get(input).await;

        let actual = actual.unwrap();
        assert_eq!(
            vec!["profile", "openid"]
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
            *actual.allowed_scopes.get("tiny-auth-frontend").unwrap()
        );
        assert_eq!(
            input,
            actual.attributes.get("uid").unwrap().as_array().unwrap()[0]
        );
        assert_eq!(
            "Bar1",
            actual.attributes.get("sn").unwrap().as_array().unwrap()[0]
        );
        assert_eq!(
            Value::from(vec!["inetOrgPerson", "posixAccount", "shadowAccount"]),
            *actual.attributes.get("objectClass").unwrap()
        );
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn invalid_connection_is_reported(name: String, password: Password) {
        let uut = simple_bind_uut(name, 1390);

        let actual = uut.verify("user01", &password, "wrong").await;

        assert!(matches!(
            actual.unwrap_err(),
            Error::BackendErrorWithContext(_)
        ));
    }

    #[fixture]
    fn image() -> GenericImage {
        let image = GenericImage::new("docker.io/bitnami/openldap", "latest")
            .with_exposed_port(1389)
            .with_volume(
                env!("CARGO_MANIFEST_DIR").to_string() + "/../../../dev/ldif",
                "/ldifs",
            )
            .with_wait_for(WaitFor::StdErrMessage {
                message: "slapd starting".to_string(),
            });
        image
    }

    fn simple_bind_uut(name: String, port: u16) -> Arc<dyn PasswordStore> {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        inject::simple_bind_store(
            name.as_str(),
            &["cn={{ user }},ou=users,dc=example,dc=org".to_string()],
            connector(&[url], Duration::from_millis(50), false),
        )
    }

    fn search_bind_uut(name: String, port: u16) -> Arc<LdapStore> {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        inject::search_bind_store(
            name.as_str(),
            connector(&[url], Duration::from_millis(50), false),
            "cn=tiny-auth-service-account,ou=users,dc=example,dc=org",
            "bitnami2",
            vec![
                LdapSearch {
                    base_dn: "ou=users,dc=nonexistent".to_string(),
                    search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                },
                LdapSearch {
                    base_dn: "ou=users,dc=example,dc=org".to_string(),
                    search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                },
            ],
            UserConfig {
                allowed_scopes_attribute: "description".to_string().into(),
            }
            .into(),
        )
    }

    fn search_bind_anonymous_uut(name: String, port: u16) -> Arc<LdapStore> {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        inject::search_bind_store(
            name.as_str(),
            connector(&[url], Duration::from_millis(50), false),
            "",
            "",
            vec![
                LdapSearch {
                    base_dn: "ou=users,dc=nonexistent".to_string(),
                    search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                },
                LdapSearch {
                    base_dn: "ou=users,dc=example,dc=org".to_string(),
                    search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                },
            ],
            UserConfig {
                allowed_scopes_attribute: "description".to_string().into(),
            }
            .into(),
        )
    }

    #[fixture]
    fn password(name: String) -> Password {
        Password::Ldap { name }
    }

    #[fixture]
    fn name() -> String {
        "LDAP".to_string()
    }
}
