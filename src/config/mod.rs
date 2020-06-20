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

pub mod parser;

use std::convert::Into;

use serde_derive::Deserialize;

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Config {
    pub store: Option<Store>,

    pub web: Web,

    pub crypto: Crypto,
}

impl Config {
    pub fn new() -> Config {
        Default::default()
    }

    pub fn merge(self, other: Self) -> Config {
        other
    }
}

#[derive(Clone, Debug, Deserialize)]
pub enum Store {
    #[serde(rename = "configuration file")]
    Config { base: String },
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Web {
    pub bind: String,

    pub domain: String,

    #[serde(default = "default_path")]
    pub path: Option<String>,

    pub tls: Option<Tls>,

    pub workers: Option<usize>,

    pub static_files: String,

    #[serde(default = "default_session_timeout")]
    pub session_timeout: Option<i64>,

    pub secret_key: String,
}

fn default_path() -> Option<String> {
    Some("".to_string())
}

fn default_session_timeout() -> Option<i64> {
    Some(3600)
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Tls {
    pub key: String,
    pub certificate: String,
    pub client_ca: Option<String>,

    #[serde(default = "default_versions")]
    pub versions: Vec<TlsVersion>,
}

fn default_versions() -> Vec<TlsVersion> {
    vec![TlsVersion::Tls1_3]
}

#[derive(Deserialize, Clone, Debug)]
pub enum TlsVersion {
    #[serde(rename = "1.3")]
    Tls1_3,

    #[serde(rename = "1.2")]
    Tls1_2,
}

impl Into<rustls::ProtocolVersion> for TlsVersion {
    fn into(self) -> rustls::ProtocolVersion {
        match self {
            Self::Tls1_3 => rustls::ProtocolVersion::TLSv1_3,
            Self::Tls1_2 => rustls::ProtocolVersion::TLSv1_2,
        }
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Crypto {
    pub key: String,

    #[serde(rename = "public key")]
    pub public_key: String,

    pub pepper: String,
}
