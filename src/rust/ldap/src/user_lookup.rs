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

use crate::authenticate::{AttributeMapping, UserCacheEntry, UserRepresentation};
use ldap3::SearchEntry;
use moka::future::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use tiny_auth_business::password::Password;
use tiny_auth_business::user::User;

pub(crate) struct UserLookup {
    pub(crate) ldap_name: String,
    pub(crate) cache: Cache<String, UserCacheEntry>,
    pub(crate) mappings: Vec<Arc<dyn AttributeMapping<User>>>,
}

impl UserLookup {
    pub(crate) async fn get_cached<'a>(&self, key: &'a str) -> UserRepresentation<'a> {
        if let Some(entry) = self.cache.get(key).await {
            UserRepresentation::CachedUser(entry)
        } else {
            UserRepresentation::Name(key)
        }
    }

    pub(crate) async fn map_to_user(&self, name: &str, search_entry: SearchEntry) -> User {
        let mut result = User {
            name: name.to_string(),
            password: Password::Ldap {
                name: self.ldap_name.to_string(),
            },
            allowed_scopes: Default::default(),
            attributes: HashMap::default(),
        };

        for user_mapping in &self.mappings {
            result = user_mapping.map(result, &search_entry);
        }

        result
            .attributes
            .insert("dn".to_string(), search_entry.dn.clone().into());
        result.attributes.extend(
            search_entry
                .attrs
                .into_iter()
                .filter(|(key, _)| !["name", "password", "allowed_scopes"].contains(&key.as_str()))
                .map(|(k, v)| (k, v.into())),
        );
        result.attributes.extend(
            search_entry
                .bin_attrs
                .into_iter()
                .map(|(k, v)| (k, v.into())),
        );

        self.cache
            .insert(name.to_string(), (search_entry.dn, result.clone()))
            .await;
        result
    }
}

pub struct UserAllowedScopesMapping {
    pub attribute: String,
}

impl AttributeMapping<User> for UserAllowedScopesMapping {
    fn map(&self, mut entity: User, search_entry: &SearchEntry) -> User {
        if let Some(attributes) = search_entry.attrs.get(&self.attribute) {
            for value in attributes {
                if let Some((client_id, scope)) = value.split_once(' ') {
                    let scopes_of_client = entity
                        .allowed_scopes
                        .entry(client_id.to_string())
                        .or_default();
                    scopes_of_client.insert(scope.to_string());
                }
            }
        }
        entity
    }
}
