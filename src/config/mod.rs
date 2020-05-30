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

use serde_derive::Deserialize;

use openssl::error::ErrorStack;
use openssl::ssl::SslAcceptor;
use openssl::ssl::SslAcceptorBuilder;
use openssl::ssl::SslMethod;

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Config {
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
    Some("/".to_string())
}

fn default_session_timeout() -> Option<i64> {
    Some(3600)
}

/// https://wiki.mozilla.org/Security/Server_Side_TLS
#[derive(Copy, Clone, Debug, Deserialize)]
pub enum TlsConfiguration {
    #[serde(rename = "modern")]
    Modern,
    #[serde(rename = "modern v5")]
    ModernV5,
    #[serde(rename = "intermediate")]
    Intermediate,
    #[serde(rename = "intermediate v5")]
    IntermediateV5,
}

impl Default for TlsConfiguration {
    fn default() -> Self {
        TlsConfiguration::ModernV5
    }
}

impl TlsConfiguration {
    pub fn to_acceptor_builder(&self) -> Result<SslAcceptorBuilder, ErrorStack> {
        let method = SslMethod::tls_server();
        match self {
            TlsConfiguration::Modern => SslAcceptor::mozilla_modern(method),
            TlsConfiguration::ModernV5 => SslAcceptor::mozilla_modern_v5(method),
            TlsConfiguration::Intermediate => SslAcceptor::mozilla_intermediate(method),
            TlsConfiguration::IntermediateV5 => SslAcceptor::mozilla_intermediate_v5(method),
        }
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Tls {
    pub configuration: TlsConfiguration,
    pub key: String,
    pub certificate: String,
    pub client_ca: Option<String>,
    pub dh_param: Option<String>,
    #[serde(rename = "1.2 ciphers")]
    pub old_ciphers: Option<String>,
    #[serde(rename = "1.3 ciphers")]
    pub ciphers: Option<String>,
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Crypto {
    pub key: String,

    #[serde(rename = "public key")]
    pub public_key: String,
}
