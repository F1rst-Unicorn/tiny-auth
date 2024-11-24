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
use testcontainers::core::WaitFor;
use testcontainers::core::{IntoContainerPort, Mount};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::{Error, Password};
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::PasswordStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_template::inject::{bind_dn_templater, ldap_search_templater};
use url::Url;

const CONTAINER_PORT: u16 = 1389;
const STORE_NAME: &str = "LDAP";

#[rstest]
#[test_log::test(tokio::test)]
pub async fn successful_simple_bind_authentication_works(
    #[future] simple_bind_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: Password,
) {
    authenticate_successfully(simple_bind_uut.await, &password).await;
}

#[rstest]
#[test_log::test(tokio::test)]
pub async fn successful_search_bind_authentication_works(
    #[future] search_bind_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: Password,
) {
    authenticate_successfully(search_bind_uut.await, &password).await;
}

#[rstest]
#[test_log::test(tokio::test)]
pub async fn successful_search_bind_anonymous_authentication_works(
    #[future] search_bind_anonymous_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: Password,
) {
    authenticate_successfully(search_bind_anonymous_uut.await, &password).await;
}

async fn authenticate_successfully(
    uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: &Password,
) {
    let actual = uut.0.verify("user01", password, "password").await;

    assert_eq!(true, actual.unwrap());
}

#[rstest]
#[test_log::test(tokio::test)]
pub async fn failing_authentication_works_with_simple_bind(
    #[future] simple_bind_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: Password,
) {
    authenticate_failing(simple_bind_uut.await, &password).await;
}

#[rstest]
#[test_log::test(tokio::test)]
pub async fn failing_authentication_works_with_search_bind(
    #[future] search_bind_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: Password,
) {
    authenticate_failing(search_bind_uut.await, &password).await;
}

#[rstest]
#[test_log::test(tokio::test)]
pub async fn failing_authentication_works_with_search_bind_anonymous(
    #[future] search_bind_anonymous_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: Password,
) {
    authenticate_failing(search_bind_anonymous_uut.await, &password).await;
}

async fn authenticate_failing(
    uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
    password: &Password,
) {
    let actual = uut.0.verify("user01", password, "wrong").await;

    assert!(!actual.unwrap());
}

#[rstest]
#[test_log::test(tokio::test)]
pub async fn invalid_connection_is_reported(password: Password) {
    let url = Url::parse(&format!("ldap://localhost:{}", CONTAINER_PORT + 1)).unwrap();
    let uut = inject::simple_bind_store(
        STORE_NAME,
        &[bind_dn_templater(
            "cn={{ user }},ou=users,dc=example,dc=org",
        )],
        connector(&[url], Duration::from_millis(50), false),
    );

    let actual = uut.verify("user01", &password, "wrong").await;

    assert!(matches!(
        actual.unwrap_err(),
        Error::BackendErrorWithContext(_)
    ));
}

#[rstest]
#[test(tokio::test)]
pub async fn getting_user_works(
    #[future] search_bind_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
) {
    let uut = search_bind_uut.await;
    let input = "user01";

    let actual = UserStore::get(uut.0.as_ref(), input).await;

    let actual = actual.unwrap();
    std::assert_eq!(
        vec!["profile", "openid"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        *actual.allowed_scopes.get("tiny-auth-frontend").unwrap()
    );
    std::assert_eq!(
        input,
        actual.attributes.get("uid").unwrap().as_array().unwrap()[0]
    );
    std::assert_eq!(
        "Bar1",
        actual.attributes.get("sn").unwrap().as_array().unwrap()[0]
    );
    std::assert_eq!(
        Value::from(vec!["inetOrgPerson", "posixAccount", "shadowAccount"]),
        *actual.attributes.get("objectClass").unwrap()
    );
}

#[rstest]
#[test(tokio::test)]
pub async fn getting_client_works(
    #[future] search_bind_uut: (Arc<LdapStore>, ContainerAsync<GenericImage>),
) {
    let uut = search_bind_uut.await;
    let input = "unit-test-client";

    let actual = ClientStore::get(uut.0.as_ref(), input).await;

    let actual = actual.unwrap();
    std::assert_eq!(
        vec!["profile", "openid"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        actual.allowed_scopes
    );
    std::assert_eq!(
        vec![
            Url::parse("http://localhost:5173/oidc-login-redirect").unwrap(),
            Url::parse("http://localhost:5173/oidc-login-redirect-silent").unwrap(),
            Url::parse("http://localhost:34344/oidc/oidc-login-redirect").unwrap(),
            Url::parse("http://localhost:34344/oidc/oidc-login-redirect-silent").unwrap(),
            Url::parse("https://localhost:34344/oidc/oidc-login-redirect").unwrap(),
            Url::parse("https://localhost:34344/oidc/oidc-login-redirect-silent").unwrap(),
        ],
        actual.redirect_uris
    );
    match actual.client_type {
        ClientType::Confidential {
            password: Password::Plain(password),
            public_key: Some(public_key),
        } => {
            std::assert_eq!("password", &password);
            std::assert_eq!(
                "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXwRakTosT7bK5YEORlQjLzpHehkuLDEu
/0pF2axbHyAGatD2QCf0KfmuylBldoyapSj8mCY11Envp0oZ4S1kYmbhfgIEwX16
uDkKrMsaTeI/ttvgR01xzMfPXyjA4Ifs
-----END PUBLIC KEY-----
",
                &public_key
            );
        }
        _ => panic!("expected confidential client"),
    }
    std::assert_eq!(
        input,
        actual.attributes.get("uid").unwrap().as_array().unwrap()[0]
    );
    std::assert_eq!(
        input,
        actual.attributes.get("sn").unwrap().as_array().unwrap()[0]
    );
    std::assert_eq!(
        Value::from(vec!["inetOrgPerson", "posixAccount", "shadowAccount"]),
        *actual.attributes.get("objectClass").unwrap()
    );
}

#[fixture]
async fn simple_bind_uut(
    #[future] container: ContainerAsync<GenericImage>,
) -> (Arc<LdapStore>, ContainerAsync<GenericImage>) {
    let container = container.await;
    let url = Url::parse(&format!(
        "ldap://localhost:{}",
        container.get_host_port_ipv4(CONTAINER_PORT).await.unwrap()
    ))
    .unwrap();

    (
        inject::simple_bind_store(
            STORE_NAME,
            &[bind_dn_templater(
                "cn={{ user }},ou=users,dc=example,dc=org",
            )],
            connector(&[url], Duration::from_millis(50), false),
        ),
        container,
    )
}

#[fixture]
async fn search_bind_uut(
    #[future] container: ContainerAsync<GenericImage>,
) -> (Arc<LdapStore>, ContainerAsync<GenericImage>) {
    let container = container.await;
    let url = Url::parse(&format!(
        "ldap://localhost:{}",
        container.get_host_port_ipv4(CONTAINER_PORT).await.unwrap()
    ))
    .unwrap();

    (
        inject::search_bind_store(
            STORE_NAME,
            connector(&[url], Duration::from_millis(50), false),
            "cn=tiny-auth-service-account,ou=users,dc=example,dc=org",
            "bitnami2",
            user_searches(),
            UserConfig {
                allowed_scopes_attribute: "description".to_owned().into(),
            }
            .into(),
            ClientConfig {
                client_type_attribute: "employeeType".to_owned().into(),
                allowed_scopes_attribute: "description".to_owned().into(),
                password_attribute: "userPassword".to_owned().into(),
                public_key_attribute: "displayName".to_owned().into(),
                redirect_uri_attribute: "givenName".to_owned().into(),
            }
            .into(),
        ),
        container,
    )
}

#[fixture]
async fn search_bind_anonymous_uut(
    #[future] container: ContainerAsync<GenericImage>,
) -> (Arc<LdapStore>, ContainerAsync<GenericImage>) {
    let container = container.await;
    let url = Url::parse(&format!(
        "ldap://localhost:{}",
        container.get_host_port_ipv4(CONTAINER_PORT).await.unwrap()
    ))
    .unwrap();

    (
        inject::search_bind_store(
            STORE_NAME,
            connector(&[url], Duration::from_millis(50), false),
            "",
            "",
            user_searches(),
            None,
            None,
        ),
        container,
    )
}

fn user_searches() -> Vec<LdapSearch> {
    vec![
        LdapSearch {
            base_dn: "ou=users,dc=nonexistent".to_owned(),
            search_filter: ldap_search_templater("(|(uid={{ user }})(mail={{ user }}))"),
        },
        LdapSearch {
            base_dn: "ou=users,dc=example,dc=org".to_owned(),
            search_filter: ldap_search_templater("(|(uid={{ user }})(mail={{ user }}))"),
        },
    ]
}

#[fixture]
async fn container() -> ContainerAsync<GenericImage> {
    GenericImage::new("docker.io/bitnami/openldap", "latest")
        .with_exposed_port(CONTAINER_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("slapd starting"))
        .with_mount(Mount::bind_mount(
            env!("CARGO_MANIFEST_DIR").to_owned() + "/../../../dev/ldif",
            "/ldifs",
        ))
        .start()
        .await
        .unwrap()
}

#[fixture]
fn password() -> Password {
    Password::Ldap {
        name: STORE_NAME.to_owned(),
    }
}
