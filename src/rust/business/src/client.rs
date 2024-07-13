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

use crate::oauth2::ClientType;
use crate::password::Password;

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;

use url::Url;

use serde::Deserialize;
use serde::Serialize;

use serde_json::Value;

use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;

use serde::de::StdError;
use thiserror::Error;
use tracing::warn;
use tracing::{debug, error};

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("backend error")]
    BackendError,
    #[error("backend error: {0}")]
    BackendErrorWithContext(#[from] Arc<dyn StdError + Send + Sync>),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,

    #[serde(with = "serde_yaml::with::singleton_map")]
    pub client_type: ClientType,

    pub redirect_uris: Vec<String>,

    #[serde(default)]
    pub allowed_scopes: BTreeSet<String>,

    #[serde(flatten)]
    pub attributes: HashMap<String, Value>,
}

impl Client {
    pub fn are_all_redirect_uris_valid(&self) -> bool {
        for url in &self.redirect_uris {
            if let Err(e) = Url::parse(url) {
                error!(
                    "Client '{}' has invalid redirect_uri {}: {}",
                    self.client_id, url, e
                );
                return false;
            }
        }
        true
    }

    pub fn is_redirect_uri_valid(&self, uri: &str) -> bool {
        self.redirect_uris.contains(&uri.to_string())
    }

    pub fn merge(mut self, mut other: Self) -> Self {
        self.client_type = match (self.client_type, other.client_type) {
            (ClientType::Public, other) => other,
            (own, ClientType::Public) => own,
            (
                ClientType::Confidential {
                    password: own_password,
                    public_key: own_key,
                },
                ClientType::Confidential {
                    password: other_password,
                    public_key: other_key,
                },
            ) => ClientType::Confidential {
                password: pick_password_by_priority(own_password, other_password),
                public_key: own_key.or(other_key),
            },
        };

        self.allowed_scopes.append(&mut other.allowed_scopes);
        self.redirect_uris.append(&mut other.redirect_uris);

        for (name, value) in other.attributes {
            match self.attributes.get_mut(&name) {
                None => {
                    self.attributes.insert(name, value);
                }
                _ => {
                    debug!(attribute = name, "ignoring duplicate");
                }
            }
        }
        self
    }

    pub fn get_decoding_key(&self, algorithm: Algorithm) -> Option<DecodingKey> {
        match (algorithm, &self.client_type) {
            (
                Algorithm::HS256,
                ClientType::Confidential {
                    password: Password::Plain(secret),
                    ..
                },
            )
            | (
                Algorithm::HS384,
                ClientType::Confidential {
                    password: Password::Plain(secret),
                    ..
                },
            )
            | (
                Algorithm::HS512,
                ClientType::Confidential {
                    password: Password::Plain(secret),
                    ..
                },
            ) => Some(DecodingKey::from_secret(secret.as_bytes())),
            (
                Algorithm::ES256,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            )
            | (
                Algorithm::ES384,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            ) => DecodingKey::from_ec_pem(key.as_bytes()).ok(),
            (
                Algorithm::RS256,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            )
            | (
                Algorithm::RS384,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            )
            | (
                Algorithm::RS512,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            )
            | (
                Algorithm::PS256,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            )
            | (
                Algorithm::PS384,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            )
            | (
                Algorithm::PS512,
                ClientType::Confidential {
                    public_key: Some(key),
                    ..
                },
            ) => DecodingKey::from_rsa_pem(key.as_bytes()).ok(),
            _ => {
                warn!(
                    "tried to authenticate with algorithm '{:?}' for which it is not configured",
                    algorithm
                );
                None
            }
        }
    }
}

fn pick_password_by_priority(first: Password, second: Password) -> Password {
    match (first, second) {
        (first @ Password::Pbkdf2HmacSha256 { .. }, Password::Pbkdf2HmacSha256 { .. }) => first,
        (Password::Pbkdf2HmacSha256 { .. }, second) => second,
        (first, Password::Pbkdf2HmacSha256 { .. }) => first,
        (first @ Password::Ldap { .. }, Password::Ldap { .. }) => first,
        (Password::Ldap { .. }, second) => second,
        (first, Password::Ldap { .. }) => first,
        (first, _) => first,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const CLIENT_1: &str = r#"
---
client_id: confidential
client_type:
  confidential:
    password:
      Pbkdf2HmacSha256:
        credential: yIwGQgK7dU7LKxageOikUK1Ci8LekYLAUqsUQqKgBXk=
        iterations: 100000
        salt: GDyTkeq//lzzWvEd6JJn8Eu227floAeFemr+4oAsXA1jb25maWRlbnRpYWw=

redirect_uris:
  - http://localhost/confidential
"#;

    pub fn get_test_client() -> Client {
        serde_yaml::from_str(CLIENT_1).unwrap()
    }
}
