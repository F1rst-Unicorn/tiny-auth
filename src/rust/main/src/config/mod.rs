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

use actix_web::cookie::SameSite;
use chrono::Duration;
use serde_derive::Deserialize;
use std::convert::From;

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub store: Option<Store>,

    #[serde(default)]
    #[serde(alias = "rate limit")]
    pub rate_limit: RateLimit,

    pub web: Web,

    pub api: Api,

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

#[derive(Clone, Debug, Deserialize)]
pub struct RateLimit {
    pub events: usize,

    #[serde(alias = "period in seconds")]
    pub period_in_seconds: i64,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            events: 3,
            period_in_seconds: Duration::minutes(5).num_seconds(),
        }
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Web {
    pub bind: String,

    #[serde(alias = "public host")]
    pub public_host: Host,

    #[serde(default = "default_path")]
    pub path: Option<String>,

    #[serde(default)]
    pub cors: Vec<String>,

    pub tls: Option<Tls>,

    pub workers: Option<usize>,

    #[serde(alias = "static files")]
    pub static_files: String,

    #[serde(default = "default_session_timeout")]
    #[serde(alias = "session timeout")]
    pub session_timeout: Option<i64>,

    #[serde(default = "default_session_same_site_policy")]
    #[serde(alias = "session same site policy")]
    pub session_same_site_policy: SameSitePolicy,

    #[serde(alias = "secret key")]
    pub secret_key: String,
}

#[allow(clippy::unnecessary_wraps)]
fn default_path() -> Option<String> {
    Some("".to_string())
}

#[allow(clippy::unnecessary_wraps)]
fn default_session_timeout() -> Option<i64> {
    Some(3600)
}

#[allow(clippy::unnecessary_wraps)]
fn default_session_same_site_policy() -> SameSitePolicy {
    SameSitePolicy::Lax
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub enum SameSitePolicy {
    #[serde(rename = "strict")]
    Strict,
    #[serde(rename = "lax")]
    Lax,
    #[serde(rename = "none")]
    None,
}

impl Default for SameSitePolicy {
    fn default() -> Self {
        Self::Lax
    }
}

impl From<SameSitePolicy> for SameSite {
    fn from(value: SameSitePolicy) -> Self {
        match value {
            SameSitePolicy::Strict => Self::Strict,
            SameSitePolicy::Lax => Self::Lax,
            SameSitePolicy::None => Self::None,
        }
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Host {
    pub domain: String,

    pub port: Option<String>,
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Api {
    #[serde(alias = "endpoint")]
    pub endpoint: String,
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Tls {
    pub key: String,

    pub certificate: String,

    #[serde(alias = "client ca")]
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

impl From<TlsVersion> for &'static rustls::SupportedProtocolVersion {
    fn from(tls_version: TlsVersion) -> Self {
        match tls_version {
            TlsVersion::Tls1_3 => &rustls::version::TLS13,
            TlsVersion::Tls1_2 => &rustls::version::TLS12,
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
