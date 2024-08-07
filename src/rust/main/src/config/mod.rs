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
use url::Url;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub store: Vec<Store>,

    #[serde(default)]
    #[serde(alias = "rate limit")]
    pub rate_limit: RateLimit,

    pub web: Web,

    pub api: Api,

    pub crypto: Crypto,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Store {
    #[serde(rename = "configuration file")]
    Config { name: String, base: String },

    #[serde(rename = "ldap")]
    Ldap {
        name: String,

        #[serde(rename = "mode")]
        mode: LdapMode,

        urls: Vec<Url>,

        #[serde(rename = "connect timeout in seconds")]
        connect_timeout_in_seconds: i64,

        #[serde(default)]
        starttls: bool,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub enum LdapMode {
    #[serde(rename = "simple bind")]
    SimpleBind {
        #[serde(rename = "bind dn format")]
        bind_dn_format: Vec<String>,
    },

    #[serde(rename = "search bind")]
    SearchBind {
        #[serde(default)]
        #[serde(rename = "bind dn")]
        bind_dn: String,
        #[serde(default)]
        #[serde(rename = "bind dn password")]
        bind_dn_password: String,
        searches: Vec<LdapSearch>,

        #[serde(default)]
        #[serde(rename = "use for")]
        use_for: LdapUsage,
    },
}

#[derive(Clone, Debug, Deserialize)]
pub struct LdapSearch {
    #[serde(rename = "base dn")]
    pub base_dn: String,
    #[serde(rename = "search filter")]
    pub search_filter: String,
}

#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct LdapUsage {
    #[serde(default)]
    pub users: Option<LdapUsageUsers>,
    #[serde(default)]
    pub clients: Option<LdapUsageClients>,
}

#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct LdapUsageUsers {
    #[serde(default)]
    pub attributes: Option<UserAttributes>,
}

#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct LdapUsageClients {
    #[serde(default)]
    pub attributes: Option<ClientAttributes>,
}

#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct UserAttributes {
    #[serde(default)]
    #[serde(rename = "allowed scopes")]
    pub allowed_scopes: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct ClientAttributes {
    #[serde(default)]
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    #[serde(default)]
    #[serde(rename = "redirect uri")]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    #[serde(rename = "password")]
    pub password: Option<String>,
    #[serde(default)]
    #[serde(rename = "public key")]
    pub public_key: Option<String>,
    #[serde(default)]
    #[serde(rename = "allowed scopes")]
    pub allowed_scopes: Option<String>,
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
    #[serde(alias = "session timeout in seconds")]
    pub session_timeout_in_seconds: Option<i64>,

    #[serde(default = "default_token_timeout_in_seconds")]
    #[serde(alias = "token timeout in seconds")]
    pub token_timeout_in_seconds: Option<i64>,

    #[serde(default = "default_refresh_token_timeout_in_seconds")]
    #[serde(alias = "refresh token timeout in seconds")]
    pub refresh_token_timeout_in_seconds: Option<i64>,

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
fn default_token_timeout_in_seconds() -> Option<i64> {
    Some(60)
}

#[allow(clippy::unnecessary_wraps)]
fn default_refresh_token_timeout_in_seconds() -> Option<i64> {
    Some(180)
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
    pub bind: String,

    #[serde(alias = "public host")]
    pub public_host: Host,

    #[serde(default = "default_path")]
    #[serde(alias = "public path")]
    pub public_path: Option<String>,

    #[serde(default = "default_path")]
    pub path: Option<String>,
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
pub struct CryptoKey {
    pub key: String,

    #[serde(rename = "public key")]
    pub public_key: String,
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Crypto {
    pub keys: Vec<CryptoKey>,

    pub pepper: String,
}
