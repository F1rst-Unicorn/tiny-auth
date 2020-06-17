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

use crate::domain::client::Client;
use crate::domain::user::User;
use crate::store::ClientStore;
use crate::store::UserStore;
use crate::util::iterate_directory;
use crate::util::read_file;

use std::collections::BTreeMap;
use std::path::PathBuf;

use log::error;

pub struct FileUserStore {
    users: BTreeMap<String, User>,
}

impl UserStore for FileUserStore {
    fn get(&self, key: &str) -> Option<User> {
        self.users.get(key).map(Clone::clone)
    }
}

impl FileUserStore {
    pub fn new(base: &str) -> Option<Self> {
        let mut users = BTreeMap::new();
        let user_store = base.to_string() + "/users";
        for file in iterate_directory(&user_store)? {
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

            let user = match serde_yaml::from_str::<User>(&raw_content) {
                Err(e) => {
                    error!("File {:?} is malformed: {}", file.path(), e);
                    return None;
                }
                Ok(user) => user,
            };

            if PathBuf::from(user.name.clone() + ".yml") != file.file_name() {
                error!(
                    "user '{}' is stored in '{:?}' but was expected to be stored in '{}.yml'",
                    user.name,
                    file.path(),
                    user.name
                );
                return None;
            }
            users.insert(user.name.clone(), user);
        }

        Some(FileUserStore { users })
    }
}

pub struct FileClientStore {
    clients: BTreeMap<String, Client>,
}

impl ClientStore for FileClientStore {
    fn get(&self, key: &str) -> Option<Client> {
        self.clients.get(key).map(Clone::clone)
    }
}

impl FileClientStore {
    pub fn new(base: &str) -> Option<Self> {
        let mut clients = BTreeMap::new();
        let client_store = base.to_string() + "/clients";
        for file in iterate_directory(&client_store)? {
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

            let client = match serde_yaml::from_str::<Client>(&raw_content) {
                Err(e) => {
                    error!("File {:?} is malformed: {}", file.path(), e);
                    return None;
                }
                Ok(client) => client,
            };

            if PathBuf::from(client.client_id.clone() + ".yml") != file.file_name() {
                error!(
                    "client '{}' is stored in '{:?}' but was expected to be stored in '{}.yml'",
                    client.client_id,
                    file.path(),
                    client.client_id
                );
                return None;
            }
            clients.insert(client.client_id.clone(), client);
        }

        Some(FileClientStore { clients })
    }
}
