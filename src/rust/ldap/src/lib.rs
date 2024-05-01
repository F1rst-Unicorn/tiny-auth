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

use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use ldap3::{drive, Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use log::{debug, error, warn};
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
use tera::{Context, Tera};
use tiny_auth_business::password::{Error, Password};
use tiny_auth_business::store::PasswordStore;
use url::Url;

struct LdapPasswordStore {
    name: String,
    urls: Vec<Url>,
    connect_timeout: Duration,
    authenticator: AuthenticatorDispatcher,
    starttls: bool,
}

impl LdapPasswordStore {
    async fn connect(&self) -> Result<Ldap, Error> {
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
        Err(Error::BackendError)
    }
}

#[async_trait]
impl PasswordStore for LdapPasswordStore {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error> {
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

        let mut ldap = self.connect().await?;
        self.authenticator
            .authenticate(&mut ldap, username, password_to_check)
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
        username: &str,
        password: &str,
    ) -> Result<bool, Error>;
}

struct SimpleBind {
    bind_dn_format: Vec<String>,
}

#[async_trait]
impl Authenticator for SimpleBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        username: &str,
        password: &str,
    ) -> Result<bool, Error> {
        for bind_template in &self.bind_dn_format {
            let bind_dn = format_username(bind_template, username)?;
            if simple_bind(ldap, &bind_dn, password).await? {
                return Ok(true);
            }
        }
        Ok(false)
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

#[async_trait]
impl Authenticator for SearchBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        username: &str,
        password: &str,
    ) -> Result<bool, Error> {
        if !simple_bind(ldap, &self.bind_dn, &self.bind_dn_password).await? {
            warn!(
                "wrong username or password for search bind mode. Username '{}'",
                self.bind_dn
            );
            return Err(Error::BackendError);
        };

        for search in &self.searches {
            let filter = format_username(&search.search_filter, username)?;
            debug!("searching in {} for {}", &search.base_dn, &filter);
            let result = match ldap
                .search(&search.base_dn, Scope::Subtree, &filter, &["dn"])
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("searching for user '{}' failed. {}", username, e);
                    return Err(Error::BackendErrorWithContext(Arc::new(e)));
                }
            };

            for entry in result.0 {
                let entry = SearchEntry::construct(entry);
                if simple_bind(ldap, &entry.dn, password).await? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

async fn simple_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> Result<bool, Error> {
    debug!("binding to LDAP as '{}'", bind_dn);
    let result = ldap
        .simple_bind(bind_dn, password)
        .await
        .map_err(|v| Arc::new(v) as Arc<dyn StdError + Send + Sync>)?;
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
            Err(Error::BackendError)
        }
    }
}

fn format_username(format: &str, username: &str) -> Result<String, Error> {
    let mut tera = Tera::default();
    let mut context = Context::new();
    context.insert("user", username);
    tera.render_str(format, &context).map_err(|e| {
        warn!("failed to construct bind dn: {}", e);
        Error::BackendErrorWithContext(Arc::new(e))
    })
}

pub mod inject {
    use crate::{LdapPasswordStore, LdapSearch, SearchBind, SimpleBind};
    use std::sync::Arc;
    use std::time::Duration;
    use tiny_auth_business::store::PasswordStore;
    use url::Url;

    pub fn simple_bind_store(
        name: &str,
        urls: &[Url],
        bind_dn_format: &[String],
        connect_timeout: Duration,
        starttls: bool,
    ) -> Arc<dyn PasswordStore> {
        Arc::new(LdapPasswordStore {
            name: name.to_string(),
            urls: urls.iter().map(Clone::clone).collect(),
            authenticator: SimpleBind {
                bind_dn_format: bind_dn_format.to_vec(),
            }
            .into(),
            connect_timeout,
            starttls,
        })
    }

    pub fn search_bind_store(
        name: &str,
        urls: &[Url],
        bind_dn: &str,
        bind_dn_password: &str,
        searches: Vec<LdapSearch>,
        connect_timeout: Duration,
        starttls: bool,
    ) -> Arc<dyn PasswordStore> {
        Arc::new(LdapPasswordStore {
            name: name.to_string(),
            urls: urls.iter().map(Clone::clone).collect(),
            authenticator: SearchBind {
                bind_dn: bind_dn.to_string(),
                bind_dn_password: bind_dn_password.to_string(),
                searches,
            }
            .into(),
            connect_timeout,
            starttls,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::fixture;
    use rstest::rstest;
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

        let actual = uut.verify("user01", &password, "bitnami1").await;

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

        let actual = uut.verify("user02", &password, "bitnami2").await;

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

        let actual = uut.verify("user02", &password, "wrong").await;

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

        let actual = uut.verify("user02", &password, "bitnami2").await;

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

        let actual = uut.verify("user02", &password, "wrong").await;

        assert_eq!(false, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn invalid_connection_is_reported(name: String, password: Password) {
        let uut = simple_bind_uut(name, 1390);

        let actual = uut.verify("user01", &password, "wrong").await;

        assert!(matches!(actual.unwrap_err(), Error::BackendError));
    }

    #[fixture]
    fn image() -> GenericImage {
        let image = GenericImage::new("docker.io/bitnami/openldap", "latest")
            .with_exposed_port(1389)
            .with_wait_for(WaitFor::StdErrMessage {
                message: "slapd starting".to_string(),
            });
        image
    }

    fn simple_bind_uut(name: String, port: u16) -> LdapPasswordStore {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        LdapPasswordStore {
            name,
            urls: vec![url],
            authenticator: SimpleBind {
                bind_dn_format: vec!["cn={{ user }},ou=users,dc=example,dc=org".to_string()],
            }
            .into(),
            connect_timeout: Duration::from_millis(50),
            starttls: false,
        }
    }

    fn search_bind_uut(name: String, port: u16) -> LdapPasswordStore {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        LdapPasswordStore {
            name,
            urls: vec![url],
            authenticator: SearchBind {
                bind_dn: "cn=user01,ou=users,dc=example,dc=org".to_string(),
                bind_dn_password: "bitnami1".to_string(),
                searches: vec![
                    LdapSearch {
                        base_dn: "ou=users,dc=nonexistent".to_string(),
                        search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                    },
                    LdapSearch {
                        base_dn: "ou=users,dc=example,dc=org".to_string(),
                        search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                    },
                ],
            }
            .into(),
            connect_timeout: Duration::from_millis(50),
            starttls: false,
        }
    }

    fn search_bind_anonymous_uut(name: String, port: u16) -> LdapPasswordStore {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        LdapPasswordStore {
            name,
            urls: vec![url],
            authenticator: SearchBind {
                bind_dn: "".to_string(),
                bind_dn_password: "".to_string(),
                searches: vec![
                    LdapSearch {
                        base_dn: "ou=users,dc=nonexistent".to_string(),
                        search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                    },
                    LdapSearch {
                        base_dn: "ou=users,dc=example,dc=org".to_string(),
                        search_filter: "(|(uid={{ user }})(mail={{ user }}))".to_string(),
                    },
                ],
            }
            .into(),
            connect_timeout: Duration::from_millis(50),
            starttls: false,
        }
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
