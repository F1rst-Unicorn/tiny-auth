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
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tiny_auth_business::client;
use tiny_auth_business::client::Client;
use tiny_auth_business::scope::Scope;
use tiny_auth_business::store::ClientStore;
use tiny_auth_business::store::ScopeStore;
use tiny_auth_business::store::UserStore;
use tiny_auth_business::user::{Error, User};
use tokio::sync::broadcast::Receiver;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, span, trace, warn, Level};

pub struct FileUserStore {
    base: PathBuf,
    users: Mutex<BTreeMap<String, User>>,
}

#[async_trait]
impl UserStore for FileUserStore {
    async fn get(&self, key: &str) -> Result<User, Error> {
        self.users
            .lock()
            .await
            .get(key)
            .cloned()
            .inspect(|_| debug!("found"))
            .ok_or(Error::NotFound)
    }
}

impl FileUserStore {
    pub async fn new(base: &Path, hot_reload_receiver: Receiver<ReloadEvent>) -> Option<Arc<Self>> {
        let mut base = PathBuf::from(base);
        base.push("users");
        let result = Self {
            base: base.clone(),
            users: Mutex::default(),
        };
        let result = Arc::new(result);
        result.clone().refresh_all(base.as_path()).await;
        tokio::spawn(result.clone().listen_for_reload_events(hot_reload_receiver));
        Some(result)
    }

    async fn listen_for_reload_events(
        self: Arc<Self>,
        mut hot_reload_receiver: Receiver<ReloadEvent>,
    ) {
        loop {
            let this = self.clone();
            let reload_event = match hot_reload_receiver.recv().await {
                Err(e) => {
                    info!(%e, "failed to receive hot reload event");
                    continue;
                }
                Ok(v) => v,
            };

            match reload_event {
                ReloadEvent::Add(path) | ReloadEvent::Modify(path) => {
                    this.refresh(path.as_path()).await;
                }
                ReloadEvent::DirectoryChange(path) => {
                    this.refresh_all(path.as_path()).await;
                }
                ReloadEvent::Delete(path) => {
                    this.remove(path.as_path()).await;
                }
            }
        }
    }

    fn applies_to(new_path: &Path, own_path: &Path) -> bool {
        (new_path.is_dir() && new_path.ends_with(own_path))
            || (!new_path.is_dir()
                && new_path
                    .parent()
                    .map(|v| v.ends_with(own_path))
                    .unwrap_or(false))
    }

    pub async fn refresh(self: Arc<Self>, path: &Path) {
        if !Self::applies_to(path, &self.base) {
            trace!(path = %path.display(), own_path = %&self.base.display(), "path doesn't match");
            return;
        }

        let raw_content = match read_file(path) {
            Err(e) => {
                warn!(%e, "could not read file, ignoring");
                return;
            }
            Ok(content) => content,
        };
        let user = match serde_yaml::from_str::<User>(&raw_content) {
            Err(e) => {
                error!(%e, "file is malformed");
                return;
            }
            Ok(v) => v,
        };
        let user = match Self::validate_file_name(user, path) {
            None => return,
            Some(v) => v,
        };
        let username = user.name.clone();
        self.users.lock().await.insert(user.name.clone(), user);

        let cid_span = span!(Level::DEBUG, "cid", user = username);
        let _guard = cid_span.enter();
        info!("user refreshed");
    }

    pub async fn remove(self: Arc<Self>, path: &Path) {
        if !Self::applies_to(path, &self.base) {
            trace!(path = %path.display(), own_path = %&self.base.display(), "path doesn't match");
            return;
        }

        let username = path.file_stem().unwrap().to_string_lossy().to_string();
        self.users.lock().await.remove(&username);

        let cid_span = span!(Level::DEBUG, "cid", user = username);
        let _guard = cid_span.enter();
        info!("user removed");
    }

    pub async fn refresh_all(self: Arc<Self>, path: &Path) -> Option<()> {
        if !Self::applies_to(path, &self.base) {
            trace!(path = %path.display(), own_path = %&self.base.display(), "path doesn't match");
            return None;
        }
        let read_users = read_object(
            self.base.to_string_lossy().as_ref(),
            Self::validate_file_name,
        )?;
        let mut users = self.users.lock().await;
        users.clear();
        read_users
            .into_iter()
            .map(|v| (v.name.clone(), v))
            .for_each(|v| {
                users.insert(v.0, v.1);
            });
        info!("users refreshed");
        Some(())
    }

    fn validate_file_name(user: User, file: &Path) -> Option<User> {
        if PathBuf::from(user.name.clone() + ".yml") != file.file_name().unwrap() {
            let cid_span = span!(Level::DEBUG, "cid", user = user.name,
                expected_filename = user.name.clone() + ".yml",
                actual_filename = ?file);
            let _guard = cid_span.enter();
            error!("user is stored in wrong file");
            return None;
        }
        Some(user)
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
                if PathBuf::from(client.client_id.clone() + ".yml") != file.file_name().unwrap() {
                    error!(client = client.client_id,
                        expected_filename = client.client_id.clone() + ".yml",
                        actual_filename = ?file,
                        "client is stored in wrong file",
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
                    error!(name = scope.name, "Invalid scope");
                    return None;
                }

                if PathBuf::from(scope.name.clone() + ".yml") != file.file_name().unwrap() {
                    error!(scope = scope.name,
                        expected_filename = scope.name.clone() + ".yml",
                        actual_filename = ?file,
                        "scope is stored in wrong file",
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

#[derive(Clone)]
pub enum ReloadEvent {
    Add(PathBuf),
    Modify(PathBuf),
    Delete(PathBuf),
    DirectoryChange(PathBuf),
}

#[instrument(name = "iterate_directory", skip(transformer))]
fn read_object<O, T>(base: &str, transformer: T) -> Option<Vec<O>>
where
    O: for<'a> Deserialize<'a>,
    T: Fn(O, &Path) -> Option<O>,
{
    let mut result = Vec::default();
    for file in iterate_directory(base)? {
        let file = match file {
            Err(e) => {
                error!(%e, "could not read store file");
                return None;
            }
            Ok(f) => {
                if !f.path().is_file() {
                    error!(file = ?f.path(),
                        "not a file. Only files are allowed inside the store");
                    return None;
                }
                f
            }
        };
        let _guard = span!(Level::INFO, "read_file", file = ?file.path()).entered();
        let raw_content = match read_file(file.path()) {
            Err(e) => {
                error!(%e, "could not read file");
                return None;
            }
            Ok(content) => content,
        };

        let object = match serde_yaml::from_str::<O>(&raw_content) {
            Err(e) => {
                error!(%e, "file is malformed");
                return None;
            }
            Ok(v) => v,
        };

        let object = transformer(object, &file.path())?;
        result.push(object);
    }
    Some(result)
}
