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

use crate::data::password::{pick_password_by_priority, Password};
use crate::data::scope::merge_attributes;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::collections::HashMap;
use tracing::warn;
use url::Url;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    #[serde(rename = "public")]
    Public,

    #[serde(rename = "confidential")]
    Confidential {
        #[serde(with = "serde_yaml::with::singleton_map")]
        password: Password,

        #[serde(alias = "public key")]
        public_key: Option<String>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,

    #[serde(with = "serde_yaml::with::singleton_map")]
    pub client_type: ClientType,

    pub redirect_uris: Vec<Url>,

    #[serde(default)]
    pub allowed_scopes: BTreeSet<String>,

    #[serde(flatten)]
    pub attributes: HashMap<String, Value>,
}

impl Client {
    pub fn is_redirect_uri_valid(&self, uri: &Url) -> bool {
        self.redirect_uris.contains(uri)
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

        self.attributes = match merge_attributes(self.attributes, other.attributes) {
            Err(e) => {
                warn!(%e, "clearing client attributes");
                HashMap::default()
            }
            Ok(Value::Object(attributes)) => attributes.into_iter().collect(),
            Ok(_) => {
                warn!("clearing client attributes because merging returned no object");
                HashMap::default()
            }
        };
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
