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

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Config {
    pub http: Http,

    pub web: Web,
}

impl Config {
    pub fn new() -> Config {
        Default::default()
    }

    pub fn merge(self, mut other: Self) -> Config {
        other
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Http {}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Web {
    pub bind: String,

    pub domain: String,

    #[serde(default = "default_path")]
    pub path: Option<String>,

    pub tls: Option<Tls>,

    pub static_files: String,

    #[serde(default = "default_session_timeout")]
    pub session_timeout: Option<i64>,
}

fn default_path() -> Option<String> {
    Some("/".to_string())
}

fn default_session_timeout() -> Option<i64> {
    Some(3600)
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct Tls {
    pub key: String,
    pub certificate: String,
}
