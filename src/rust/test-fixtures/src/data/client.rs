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
use lazy_static::lazy_static;
use serde_yaml;
use std::collections::BTreeSet;
use tiny_auth_business::data::client::{Client, ClientType};
use tiny_auth_business::token::TokenValidator;
use url::Url;

pub trait ClientExt {
    fn with_allowed_scopes<'a, S>(self, scopes: impl IntoIterator<Item = &'a S>) -> Self
    where
        S: ToOwned<Owned = String> + ?Sized + 'a;
}

impl ClientExt for Client {
    fn with_allowed_scopes<'a, S>(mut self, scopes: impl IntoIterator<Item = &'a S>) -> Self
    where
        S: ToOwned<Owned = String> + ?Sized + 'a,
    {
        self.allowed_scopes = scopes.into_iter().map(ToOwned::to_owned).collect();
        self
    }
}

pub const CLIENT: &str = r#"
---
client_id: confidential
client_type:
  confidential:
    password:
      plain: confidential

redirect_uris:
  - http://localhost/client1
allowed_scopes:
  - email
"#;

lazy_static! {
    pub static ref DEFAULT_CLIENT: Client = Client {
        client_id: "".to_owned(),
        client_type: ClientType::Public,
        redirect_uris: vec![],
        allowed_scopes: Default::default(),
        attributes: Default::default(),
    };
    pub static ref PUBLIC_CLIENT: Client = Client {
        client_id: "client2".to_owned(),
        client_type: ClientType::Public,
        redirect_uris: vec![Url::parse("http://localhost/client2").unwrap()],
        allowed_scopes: BTreeSet::from_iter(vec!["email".to_owned()]),
        attributes: Default::default(),
    };
    pub static ref TINY_AUTH_FRONTEND: Client = Client {
        client_id: TokenValidator::TINY_AUTH_FRONTEND_CLIENT_ID.to_owned(),
        client_type: ClientType::Public,
        redirect_uris: vec![Url::parse("http://localhost").unwrap()],
        allowed_scopes: BTreeSet::from_iter(vec!["email".to_owned()]),
        attributes: Default::default(),
    };
    pub static ref CONFIDENTIAL_CLIENT: Client = serde_yaml::from_str(CLIENT).unwrap();
}
