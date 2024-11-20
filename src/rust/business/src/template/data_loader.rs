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
use serde_json::Value;
use std::collections::BTreeMap;

pub struct DataLoaderContext {
    pub assigned_to: Vec<i32>,
    pub root_type: Root,
    pub root: Value,
    pub loaded_data: BTreeMap<String, Value>,
}

pub enum Root {
    User,
    Client,
}

impl AsRef<str> for Root {
    fn as_ref(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Client => "client",
        }
    }
}
