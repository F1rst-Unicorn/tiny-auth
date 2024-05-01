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
use ldap3::{drive, Ldap, LdapConnAsync, LdapConnSettings};
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
    bind_dn_format: Vec<String>,
    connect_timeout: Duration,
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

    async fn authenticate(
        &self,
        mut ldap: Ldap,
        username: &str,
        password: &str,
    ) -> Result<bool, Error> {
        for bind_template in &self.bind_dn_format {
            let bind_dn = Self::format_username(bind_template, username)?;
            debug!("authenticating to LDAP '{}' as '{}'", self.name, bind_dn);
            let result = ldap
                .simple_bind(&bind_dn, password)
                .await
                .map_err(|v| Arc::new(v) as Arc<dyn StdError + Send + Sync>)?;
            match result.rc {
                0 => return Ok(true),
                49 => {
                    debug!("wrong username or password");
                    continue;
                }
                v => {
                    warn!(
                        "Unexpected LDAP result code while binding: {}. {}",
                        v, result.text
                    );
                    return Err(Error::BackendError);
                }
            }
        }
        Ok(false)
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

        let ldap = self.connect().await?;
        self.authenticate(ldap, username, password_to_check).await
    }
}

pub mod inject {
    use crate::LdapPasswordStore;
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
            bind_dn_format: bind_dn_format.to_vec(),
            connect_timeout,
            starttls,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::LdapPasswordStore;
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
        let uut = uut(name, container.get_host_port_ipv4(1389));

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
        let uut = uut(name, container.get_host_port_ipv4(1389));

        let actual = uut.verify("user01", &password, "wrong").await;

        assert_eq!(false, actual.unwrap());
    }

    #[rstest]
    #[test(tokio::test)]
    pub async fn invalid_connection_is_reported(name: String, password: Password) {
        let uut = uut(name, 1390);

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

    fn uut(name: String, port: u16) -> LdapPasswordStore {
        let url = Url::parse(&format!("ldap://localhost:{}", port)).unwrap();

        LdapPasswordStore {
            name,
            urls: vec![url],
            bind_dn_format: vec!["cn={{ user }},ou=users,dc=example,dc=org".to_string()],
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
