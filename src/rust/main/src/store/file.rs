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

use crate::util::iterate_directory;
use crate::util::read_file;
use async_trait::async_trait;
use log::error;
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tiny_auth_business::client;
use tiny_auth_business::client::Client;
use tiny_auth_business::scope::Scope;
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::ScopeStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_business::user::{Error, User};

#[derive(Default)]
pub struct FileUserStore {
    users: BTreeMap<String, User>,
}

#[async_trait]
impl UserStore for FileUserStore {
    async fn get(&self, key: &str) -> Result<User, Error> {
        self.users.get(key).cloned().ok_or(Error::NotFound)
    }
}

impl FileUserStore {
    pub fn read_users(&mut self, base: &str) -> bool {
        if let Some(users) = read_object(
            (base.to_string() + "/users").as_str(),
            |user: User, file| {
                if PathBuf::from(user.name.clone() + ".yml") != file.file_name() {
                    error!(
                        "user '{}' is stored in '{:?}' but was expected to be stored in '{}.yml'",
                        user.name,
                        file.path(),
                        user.name
                    );
                    return None;
                }
                Some(user)
            },
        ) {
            users
                .into_iter()
                .map(|v| (v.name.clone(), v))
                .for_each(|v| {
                    self.users.insert(v.0, v.1);
                });
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
pub struct FileClientStore {
    clients: BTreeMap<String, Client>,
}

#[async_trait]
impl ClientStore for FileClientStore {
    async fn get(&self, key: &str) -> Result<Client, client::Error> {
        self.clients
            .get(key)
            .cloned()
            .ok_or(client::Error::NotFound)
    }
}

impl FileClientStore {
    pub fn read_clients(&mut self, base: &str) -> bool {
        if let Some(clients) = read_object(
            (base.to_string() + "/clients").as_str(),
            |client: Client, file| {
                if PathBuf::from(client.client_id.clone() + ".yml") != file.file_name() {
                    error!(
                        "client '{}' is stored in '{:?}' but was expected to be stored in '{}.yml'",
                        client.client_id,
                        file.path(),
                        client.client_id
                    );
                    return None;
                }

                if !client.are_all_redirect_uris_valid() {
                    return None;
                }
                Some(client)
            },
        ) {
            clients
                .into_iter()
                .map(|v| (v.client_id.clone(), v))
                .for_each(|v| {
                    self.clients.insert(v.0, v.1);
                });
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
pub struct FileScopeStore {
    scopes: BTreeMap<String, Scope>,
}

impl ScopeStore for FileScopeStore {
    fn get(&self, key: &str) -> Option<Scope> {
        self.scopes.get(key).cloned()
    }

    fn get_scope_names(&self) -> Vec<String> {
        self.scopes.keys().map(Clone::clone).collect()
    }
}

impl FileScopeStore {
    pub fn read_scopes(&mut self, base: &str) -> bool {
        if let Some(scopes) = read_object(
            (base.to_string() + "/scopes").as_str(),
            |scope: Scope, file| {
                let pattern = Regex::new(r"^[\x21\x23-\x5B\x5D-\x7E]+$").unwrap();
                if !pattern.is_match(&scope.name) {
                    error!("Invalid scope name {}", scope.name);
                    return None;
                }

                if PathBuf::from(scope.name.clone() + ".yml") != file.file_name() {
                    error!(
                        "scope '{}' is stored in '{:?}' but was expected to be stored in '{}.yml'",
                        scope.name,
                        file.path(),
                        scope.name
                    );
                    return None;
                }
                Some(scope)
            },
        ) {
            scopes
                .into_iter()
                .map(|v| (v.name.clone(), v))
                .for_each(|v| {
                    self.scopes.insert(v.0, v.1);
                });
            true
        } else {
            false
        }
    }
}

fn read_object<O, T>(base: &str, transformer: T) -> Option<Vec<O>>
where
    O: for<'a> Deserialize<'a>,
    T: Fn(O, &std::fs::DirEntry) -> Option<O>,
{
    let mut result = Vec::default();
    let directory_entries = iterate_directory(base)?;
    for file in directory_entries {
        let file = match file {
            Err(e) => {
                error!("Could not read store file: {}", e);
                return None;
            }
            Ok(f) => {
                if !f.path().is_file() {
                    error!(
                        "{:?} is no file. Only files are allowed inside the store",
                        f.path()
                    );
                    return None;
                }
                f
            }
        };
        let raw_content = match read_file(file.path()) {
            Err(e) => {
                error!("Could not read file {:?}: {}", file.path(), e);
                return None;
            }
            Ok(content) => content,
        };

        let object = match serde_yaml::from_str::<O>(&raw_content) {
            Err(e) => {
                error!("File {:?} is malformed: {}", file.path(), e);
                return None;
            }
            Ok(v) => v,
        };

        let object = transformer(object, &file)?;
        result.push(object);
    }
    Some(result)
}
