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

use crate::lookup::types::AttributeMapping;
use crate::lookup::types::DistinguishedName;
use ldap3::SearchEntry;
use moka::future::Cache;
use std::sync::Arc;
use tiny_auth_business::client::Client;
use tiny_auth_business::oauth2::ClientType;
use tiny_auth_business::password::Password;
use tracing::{debug, error, trace};
use url::Url;

pub(crate) type ClientCacheEntry = (DistinguishedName, Client);

pub enum ClientRepresentation {
    Name,
    Missing,
    CachedClient(ClientCacheEntry),
}

pub(crate) struct ClientLookup {
    pub(crate) ldap_name: String,
    pub(crate) cache: Cache<String, Option<ClientCacheEntry>>,
    pub(crate) mappings: Vec<Arc<dyn AttributeMapping<Client>>>,
}

impl ClientLookup {
    pub(crate) async fn get_cached(&self, key: &str) -> ClientRepresentation {
        match self.cache.get(key).await {
            Some(Some(entry)) => {
                debug!("Cache hit");
                ClientRepresentation::CachedClient(entry)
            }
            Some(None) => {
                debug!("Cache hit for absent client");
                ClientRepresentation::Missing
            }
            None => {
                debug!("Cache miss");
                ClientRepresentation::Name
            }
        }
    }

    pub(crate) async fn record_missing(&self, name: &str) {
        self.cache.insert(name.to_string(), None).await;
    }

    pub(crate) async fn map_to_client(&self, name: &str, search_entry: SearchEntry) -> Client {
        let mut result = Client {
            client_id: name.to_string(),
            client_type: ClientType::Confidential {
                password: Password::Ldap {
                    name: self.ldap_name.clone(),
                },
                public_key: None,
            },
            redirect_uris: vec![],
            allowed_scopes: Default::default(),
            attributes: Default::default(),
        };

        for client_mapping in &self.mappings {
            result = client_mapping.map(result, &search_entry);
        }

        result
            .attributes
            .insert("dn".to_string(), search_entry.dn.clone().into());
        result.attributes.extend(
            search_entry
                .attrs
                .into_iter()
                .filter(|(key, _)| {
                    ![
                        "client_id",
                        "client_type",
                        "redirect_uris",
                        "allowed_scopes",
                    ]
                    .contains(&key.as_str())
                })
                .map(|(k, v)| (k, v.into())),
        );
        result.attributes.extend(
            search_entry
                .bin_attrs
                .into_iter()
                .map(|(k, v)| (k, v.into())),
        );

        trace!("Caching client {}", name);
        self.cache
            .insert(name.to_string(), Some((search_entry.dn, result.clone())))
            .await;
        result
    }
}

pub struct ClientTypeMapping {
    pub attribute: String,
}

impl AttributeMapping<Client> for ClientTypeMapping {
    fn map(&self, mut entity: Client, search_entry: &SearchEntry) -> Client {
        if let Some(attributes) = search_entry.attrs.get(&self.attribute) {
            if attributes.len() > 1 {
                error!(
                    "Not mapping multiple client type attributes {} for client {}",
                    self.attribute, entity.client_id
                );
                return entity;
            }
            let client_type = attributes.first().cloned().unwrap();
            if client_type == "public" {
                entity.client_type = ClientType::Public;
            } else if client_type != "confidential" {
                error!(
                    "Invalid client type attribute value {} for client {}",
                    self.attribute, entity.client_id
                );
            }
        }
        entity
    }
}

pub struct ClientAllowedScopesMapping {
    pub attribute: String,
}

impl AttributeMapping<Client> for ClientAllowedScopesMapping {
    fn map(&self, mut entity: Client, search_entry: &SearchEntry) -> Client {
        if let Some(attributes) = search_entry.attrs.get(&self.attribute) {
            for value in attributes {
                entity.allowed_scopes.insert(value.clone());
            }
        }
        entity
    }
}

pub struct ClientRedirectUriMapping {
    pub attribute: String,
}

impl AttributeMapping<Client> for ClientRedirectUriMapping {
    fn map(&self, mut entity: Client, search_entry: &SearchEntry) -> Client {
        if let Some(attributes) = search_entry.attrs.get(&self.attribute) {
            for url in attributes {
                if let Err(e) = Url::parse(url) {
                    error!(
                        "Client '{}' has invalid redirect_uri {} which will be ignored: {}",
                        entity.client_id, url, e
                    );
                    continue;
                }

                entity.redirect_uris.push(url.clone());
            }
        }
        entity
    }
}

pub struct ClientPasswordMapping {
    pub attribute: String,
}

impl AttributeMapping<Client> for ClientPasswordMapping {
    fn map(&self, mut entity: Client, search_entry: &SearchEntry) -> Client {
        if let Some(attributes) = search_entry.attrs.get(&self.attribute) {
            if attributes.len() > 1 {
                error!(
                    "Not mapping multiple password attributes {} for client {}",
                    self.attribute, entity.client_id
                );
            } else if let ClientType::Confidential {
                ref mut password, ..
            } = &mut entity.client_type
            {
                *password = Password::Plain(attributes.first().cloned().unwrap());
            } else {
                error!(
                    "Ignoring public key attribute {} for public client {}",
                    self.attribute, entity.client_id
                );
            }
        }
        entity
    }
}

pub struct ClientPublicKeyMapping {
    pub attribute: String,
}

impl AttributeMapping<Client> for ClientPublicKeyMapping {
    fn map(&self, mut entity: Client, search_entry: &SearchEntry) -> Client {
        if let Some(attributes) = search_entry.attrs.get(&self.attribute) {
            if attributes.len() > 1 {
                error!(
                    "Not mapping multiple public key attributes {} for client {}",
                    self.attribute, entity.client_id
                );
            } else if let ClientType::Confidential {
                ref mut public_key, ..
            } = &mut entity.client_type
            {
                *public_key = Some(attributes.first().cloned().unwrap());
            } else {
                error!(
                    "Ignoring public key attribute {} for public client {}",
                    self.attribute, entity.client_id
                );
            }
        }
        entity
    }
}
