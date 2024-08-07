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

use serde_derive::Serialize;

#[derive(Serialize, Clone)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn with_keys(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    pub fn get(&self, kid: &str) -> Option<Jwk> {
        for key in &self.keys {
            if key.key_id == kid {
                return Some(key.clone());
            }
        }
        None
    }
}

#[derive(Serialize, Clone)]
pub struct Jwk {
    #[serde(rename = "kid")]
    pub key_id: String,

    #[serde(rename = "kty")]
    key_type: String,

    #[serde(rename = "use")]
    usage: String,

    #[serde(rename = "x5u")]
    url: String,

    #[serde(rename = "key_ops")]
    key_operations: Vec<String>,

    #[serde(flatten)]
    key: Key,
}

impl Jwk {
    pub fn new_rsa(id: String, url: String, n: String, e: String) -> Self {
        Self {
            key_id: id,
            key_type: "RSA".to_string(),
            usage: "sig".to_string(),
            url,
            key_operations: vec!["sign".to_string(), "verify".to_string()],
            key: Key::Rsa { n, e },
        }
    }

    pub fn new_ecdsa(id: String, url: String, crv: String, x: String, y: String) -> Self {
        Self {
            key_id: id,
            key_type: "EC".to_string(),
            usage: "sig".to_string(),
            url,
            key_operations: vec!["sign".to_string(), "verify".to_string()],
            key: Key::Ecdsa { crv, x, y },
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(untagged)]
enum Key {
    Rsa { n: String, e: String },
    Ecdsa { crv: String, x: String, y: String },
}
