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

use super::*;
use crate::inject::{connector, ClientConfig, UserConfig};
use crate::store::LdapStore;
use pretty_assertions::assert_eq;
use rstest::fixture;
use rstest::rstest;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use test_log::test;
use testcontainers::clients::Cli;
use testcontainers::core::WaitFor;
use testcontainers::GenericImage;
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::{Error, Password};
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::PasswordStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_template::inject::bind_dn_templater;
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
pub async fn failing_authentication_works(image: GenericImage, name: String, password: Password) {
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

    let actual = UserStore::get(uut.as_ref(), input).await;

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
pub async fn getting_client_works(image: GenericImage, name: String) {
    let cli = Cli::default();
    let container = cli.run(image);
    let uut = search_bind_uut(name, container.get_host_port_ipv4(1389));
    let input = "unit-test-client";

    let actual = ClientStore::get(uut.as_ref(), input).await;

    let actual = actual.unwrap();
    assert_eq!(
        vec!["profile", "openid"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>(),
        actual.allowed_scopes
    );
    assert_eq!(
        vec![
            "http://localhost:5173/oidc-login-redirect",
            "http://localhost:5173/oidc-login-redirect-silent",
            "http://localhost:34344/oidc/oidc-login-redirect",
            "http://localhost:34344/oidc/oidc-login-redirect-silent",
            "https://localhost:34344/oidc/oidc-login-redirect",
            "https://localhost:34344/oidc/oidc-login-redirect-silent"
        ],
        actual.redirect_uris
    );
    match actual.client_type {
        ClientType::Confidential {
            password: Password::Plain(password),
            public_key: Some(public_key),
        } => {
            assert_eq!("password", &password);
            assert_eq!(
                "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXwRakTosT7bK5YEORlQjLzpHehkuLDEu
/0pF2axbHyAGatD2QCf0KfmuylBldoyapSj8mCY11Envp0oZ4S1kYmbhfgIEwX16
uDkKrMsaTeI/ttvgR01xzMfPXyjA4Ifs
-----END PUBLIC KEY-----
",
                &public_key
            );
        }
        _ => assert!(false),
    }
    assert_eq!(
        input,
        actual.attributes.get("uid").unwrap().as_array().unwrap()[0]
    );
    assert_eq!(
        input,
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
        &[bind_dn_templater(
            "cn={{ user }},ou=users,dc=example,dc=org",
        )],
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
                search_filter: bind_dn_templater("(|(uid={{ user }})(mail={{ user }}))"),
            },
            LdapSearch {
                base_dn: "ou=users,dc=example,dc=org".to_string(),
                search_filter: bind_dn_templater("(|(uid={{ user }})(mail={{ user }}))"),
            },
        ],
        UserConfig {
            allowed_scopes_attribute: "description".to_string().into(),
        }
        .into(),
        ClientConfig {
            client_type_attribute: "employeeType".to_string().into(),
            allowed_scopes_attribute: "description".to_string().into(),
            password_attribute: "userPassword".to_string().into(),
            public_key_attribute: "displayName".to_string().into(),
            redirect_uri_attribute: "givenName".to_string().into(),
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
                search_filter: bind_dn_templater("(|(uid={{ user }})(mail={{ user }}))"),
            },
            LdapSearch {
                base_dn: "ou=users,dc=example,dc=org".to_string(),
                search_filter: bind_dn_templater("(|(uid={{ user }})(mail={{ user }}))"),
            },
        ],
        None,
        None,
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
