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

use crate::authenticate::{LdapSearch, SearchBind, SimpleBind};
use crate::connect::Connector;
use crate::health::LdapHealth;
use crate::lookup::client_lookup::{
    ClientAllowedScopesMapping, ClientCacheEntry, ClientLookup, ClientPasswordMapping,
    ClientPublicKeyMapping, ClientRedirectUriMapping, ClientTypeMapping,
};
use crate::lookup::user_lookup::{UserAllowedScopesMapping, UserCacheEntry, UserLookup};
use crate::lookup::AttributeMapping;
use crate::store::LdapStore;
use moka::future::Cache;
use moka::policy::EvictionPolicy;
use std::sync::Arc;
use std::time::Duration;
use tiny_auth_business::client::Client;
use tiny_auth_business::health::HealthCheckCommand;
use tiny_auth_business::store::PasswordStore;
use tiny_auth_business::template::{bind_dn::BindDnContext, Templater};
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
    bind_dn_templates: &[Arc<dyn for<'a> Templater<BindDnContext<'a>>>],
    connector: Connector,
) -> Arc<dyn PasswordStore> {
    Arc::new(LdapStore {
        name: name.to_owned(),
        connector,
        authenticator: SimpleBind {
            bind_dn_templates: bind_dn_templates.to_vec(),
        }
        .into(),
        user_lookup: None,
        client_lookup: None,
    })
}

pub struct UserConfig {
    pub allowed_scopes_attribute: Option<String>,
}

pub struct ClientConfig {
    pub client_type_attribute: Option<String>,
    pub allowed_scopes_attribute: Option<String>,
    pub password_attribute: Option<String>,
    pub public_key_attribute: Option<String>,
    pub redirect_uri_attribute: Option<String>,
}

pub fn search_bind_store(
    name: &str,
    connector: Connector,
    bind_dn: &str,
    bind_dn_password: &str,
    searches: Vec<LdapSearch>,
    user_config: Option<UserConfig>,
    client_config: Option<ClientConfig>,
) -> Arc<LdapStore> {
    Arc::new(LdapStore {
        name: name.to_owned(),
        connector,
        authenticator: SearchBind {
            bind_dn: bind_dn.to_owned(),
            bind_dn_password: bind_dn_password.to_owned(),
            searches,
        }
        .into(),
        user_lookup: user_config.map(|user_config| UserLookup {
            ldap_name: name.to_owned(),
            cache: user_cache(name),
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
        client_lookup: client_config.map(|client_config| ClientLookup {
            ldap_name: name.to_owned(),
            cache: client_cache(name),
            mappings: None
                .into_iter()
                .chain(client_config.client_type_attribute.map(|v| {
                    Arc::new(ClientTypeMapping { attribute: v })
                        as Arc<dyn AttributeMapping<Client>>
                }))
                .chain(client_config.allowed_scopes_attribute.map(|v| {
                    Arc::new(ClientAllowedScopesMapping { attribute: v })
                        as Arc<dyn AttributeMapping<Client>>
                }))
                .chain(client_config.password_attribute.map(|v| {
                    Arc::new(ClientPasswordMapping { attribute: v })
                        as Arc<dyn AttributeMapping<Client>>
                }))
                .chain(client_config.public_key_attribute.map(|v| {
                    Arc::new(ClientPublicKeyMapping { attribute: v })
                        as Arc<dyn AttributeMapping<Client>>
                }))
                .chain(client_config.redirect_uri_attribute.map(|v| {
                    Arc::new(ClientRedirectUriMapping { attribute: v })
                        as Arc<dyn AttributeMapping<Client>>
                }))
                .collect(),
        }),
    })
}

pub fn simple_bind_check(connector: Connector) -> impl HealthCheckCommand {
    LdapHealth {
        connector,
        authenticator: SimpleBind {
            bind_dn_templates: vec![],
        }
        .into(),
    }
}

pub fn search_bind_check(
    connector: Connector,
    bind_dn: &str,
    bind_dn_password: &str,
) -> impl HealthCheckCommand {
    LdapHealth {
        connector,
        authenticator: SearchBind {
            bind_dn: bind_dn.to_owned(),
            bind_dn_password: bind_dn_password.to_owned(),
            searches: Default::default(),
        }
        .into(),
    }
}

fn user_cache(name: &str) -> Cache<String, Option<UserCacheEntry>> {
    Cache::builder()
        .name(format!("tiny-auth ldap store {name}").as_str())
        .eviction_policy(EvictionPolicy::tiny_lfu())
        .time_to_idle(Duration::from_secs(10))
        .build()
}

fn client_cache(name: &str) -> Cache<String, Option<ClientCacheEntry>> {
    Cache::builder()
        .name(format!("tiny-auth ldap store {name}").as_str())
        .eviction_policy(EvictionPolicy::tiny_lfu())
        .time_to_idle(Duration::from_secs(10))
        .build()
}
