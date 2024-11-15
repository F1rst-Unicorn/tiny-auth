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
use tiny_auth_business::data_loader::DataLoader;
use url::Url;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub store: Vec<Store>,

    #[serde(default)]
    #[serde(alias = "rate limit")]
    pub rate_limit: RateLimit,

    pub web: Web,

    pub api: Api,

    pub crypto: Crypto,

    pub log: Log,

    #[serde(default)]
    #[serde(alias = "hot reload")]
    pub hot_reload: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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

    #[serde(rename = "sqlite")]
    Sqlite {
        name: String,
        base: String,
        #[serde(rename = "use for")]
        use_for: SqliteUseFor,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SqliteUseFor {
    #[serde(default)]
    pub scopes: bool,
    #[serde(default)]
    pub passwords: bool,
    #[serde(default)]
    #[serde(rename = "auth codes")]
    pub auth_codes: bool,
    #[serde(default)]
    pub clients: Vec<QueryLoader>,
    #[serde(default)]
    pub users: Vec<QueryLoader>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct QueryLoader {
    pub location: String,
    pub name: String,
    pub multiplicity: Multiplicity,
    pub query: String,
    #[serde(default)]
    pub assignment: String,
}

impl TryFrom<&QueryLoader> for tiny_auth_sqlite::QueryLoader {
    type Error = &'static str;
    fn try_from(v: &QueryLoader) -> Result<Self, &'static str> {
        Ok(tiny_auth_sqlite::inject::query_loader(
            DataLoader::new(
                v.name.clone(),
                v.location.clone().try_into()?,
                v.multiplicity.into(),
            ),
            v.query.clone(),
            v.assignment.clone(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum Multiplicity {
    #[serde(rename = "to one")]
    ToOne,
    #[serde(rename = "to many")]
    ToMany,
}

impl From<Multiplicity> for tiny_auth_business::data_loader::Multiplicity {
    fn from(value: Multiplicity) -> Self {
        match value {
            Multiplicity::ToOne => Self::ToOne,
            Multiplicity::ToMany => Self::ToMany,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
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

    #[serde(default = "default_shutdown_timeout")]
    #[serde(rename = "shutdown timeout in seconds")]
    pub shutdown_timeout: u64,

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

fn default_shutdown_timeout() -> u64 {
    30
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SameSitePolicy {
    #[serde(rename = "strict")]
    Strict,
    #[default]
    #[serde(rename = "lax")]
    Lax,
    #[serde(rename = "none")]
    None,
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

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Host {
    pub domain: String,

    pub port: Option<String>,
}

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
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

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct CryptoKey {
    pub key: String,

    #[serde(rename = "public key")]
    pub public_key: String,
}

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Crypto {
    pub keys: Vec<CryptoKey>,

    pub pepper: String,
}

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Log {
    pub format: Format,
    pub fields: Fields,
    pub filter: Vec<String>,
}

#[derive(Default, Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Fields {
    pub ansi: bool,
    pub file: bool,
    pub level: bool,
    #[serde(rename = "line number")]
    pub line_number: bool,
    pub target: bool,
    #[serde(rename = "thread id")]
    pub thread_id: bool,
    #[serde(rename = "thread name")]
    pub thread_name: bool,
    #[serde(rename = "span events")]
    pub span_events: bool,
    pub time: Time,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
pub enum Format {
    #[serde(rename = "compact")]
    Compact,
    #[serde(rename = "pretty")]
    Pretty,
    #[default]
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "json")]
    Json {
        flatten: bool,
        #[serde(rename = "current span")]
        current_span: bool,
        #[serde(rename = "span list")]
        span_list: bool,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
pub enum Time {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "uptime")]
    Uptime,
    #[default]
    #[serde(rename = "system")]
    SystemTime,
    #[serde(rename = "utc")]
    Utc {
        #[serde(default = "default_time_format")]
        format: String,
    },
    #[serde(rename = "local")]
    Local {
        #[serde(default = "default_time_format")]
        format: String,
    },
}

#[allow(clippy::unnecessary_wraps)]
fn default_time_format() -> String {
    "%F %T".to_string()
}
