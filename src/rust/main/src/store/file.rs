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
use tiny_auth_business::data::client::Client;
use tiny_auth_business::data::scope::Scope;
use tiny_auth_business::data::user::User;
use tiny_auth_business::store::user_store::Error;
use tiny_auth_business::store::UserStore;
use tiny_auth_business::store::{client_store, ScopeStore};
use tiny_auth_business::store::{ClientStore, ScopeStoreError};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::Receiver;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, span, trace, warn, Level};

pub struct FileStore<T> {
    base: PathBuf,
    data: RwLock<BTreeMap<String, T>>,
}

pub(crate) trait DataExt {
    fn name(&self) -> String;
    fn validate(data: Self, file: &Path) -> Option<Self>
    where
        Self: Sized;
    fn log_single_refresh(name: &str);
    fn log_single_remove(name: &str);
}

#[async_trait]
impl UserStore for FileStore<User> {
    #[instrument(skip_all, fields(store = ?self.base))]
    async fn get(&self, key: &str) -> Result<User, Error> {
        self.data
            .read()
            .await
            .get(key)
            .cloned()
            .inspect(|_| debug!("found"))
            .ok_or(Error::NotFound)
    }
}

#[async_trait]
impl ClientStore for FileStore<Client> {
    #[instrument(skip_all, fields(store = ?self.base))]
    async fn get(&self, key: &str) -> Result<Client, client_store::Error> {
        self.data
            .read()
            .await
            .get(key)
            .cloned()
            .ok_or(tiny_auth_business::store::client_store::Error::NotFound)
    }
}

#[async_trait]
impl ScopeStore for FileStore<Scope> {
    #[instrument(skip_all, fields(store = ?self.base))]
    async fn get_all(&self, keys: &[String]) -> Result<Vec<Scope>, ScopeStoreError> {
        let data = self.data.read().await;
        keys.iter()
            .map(|v| data.get(v).cloned().ok_or(ScopeStoreError::NotFound))
            .collect()
    }

    #[instrument(skip_all, fields(store = ?self.base))]
    async fn get_scope_names(&self) -> Result<Vec<String>, ScopeStoreError> {
        Ok(self.data.read().await.keys().map(Clone::clone).collect())
    }
}

impl<T: for<'a> Deserialize<'a> + Send + DataExt + 'static + Sync> FileStore<T> {
    pub async fn new(
        base: &Path,
        sub_path: &str,
        hot_reload_receiver: Receiver<ReloadEvent>,
    ) -> Option<Arc<Self>> {
        let mut base = PathBuf::from(base);
        base.push(sub_path);
        let result = Self {
            base: base.clone(),
            data: RwLock::default(),
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
                Err(RecvError::Closed) => {
                    break;
                }
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
                info!(%e, "ignoring file due to error");
                return;
            }
            Ok(content) => content,
        };
        let data_item = match serde_yaml::from_str::<T>(&raw_content) {
            Err(e) => {
                error!(%e, "file is malformed");
                return;
            }
            Ok(v) => v,
        };
        let data_item = match T::validate(data_item, path) {
            None => return,
            Some(v) => v,
        };
        let name = data_item.name().clone();
        self.data
            .write()
            .await
            .insert(data_item.name().clone(), data_item);

        T::log_single_refresh(&name)
    }

    pub async fn remove(self: Arc<Self>, path: &Path) {
        if !Self::applies_to(path, &self.base) {
            trace!(path = %path.display(), own_path = %&self.base.display(), "path doesn't match");
            return;
        }

        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        self.data.write().await.remove(&name);

        T::log_single_remove(&name)
    }

    pub async fn refresh_all(self: Arc<Self>, path: &Path) -> Option<()> {
        if !Self::applies_to(path, &self.base) {
            trace!(path = %path.display(), own_path = %&self.base.display(), "path doesn't match");
            return None;
        }
        let read_objects = read_objects(self.base.to_string_lossy().as_ref(), T::validate)?;
        let mut objects = self.data.write().await;
        objects.clear();
        read_objects
            .into_iter()
            .map(|v| (v.name().clone(), v))
            .for_each(|v| {
                objects.insert(v.0, v.1);
            });
        info!("data refreshed");
        Some(())
    }
}

impl DataExt for User {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn validate(user: User, file: &Path) -> Option<User> {
        if PathBuf::from(user.name.clone() + ".yml") != file.file_name()? {
            let cid_span = span!(Level::DEBUG, "cid", user = user.name,
                expected_filename = user.name.clone() + ".yml",
                actual_filename = ?file);
            let _guard = cid_span.enter();
            error!("user is stored in wrong file");
            return None;
        }
        Some(user)
    }

    fn log_single_refresh(name: &str) {
        let cid_span = span!(Level::DEBUG, "cid", user = name);
        let _guard = cid_span.enter();
        info!("user refreshed");
    }

    fn log_single_remove(name: &str) {
        let cid_span = span!(Level::DEBUG, "cid", user = name);
        let _guard = cid_span.enter();
        info!("user removed");
    }
}

impl DataExt for Client {
    fn name(&self) -> String {
        self.client_id.clone()
    }

    fn validate(client: Client, file: &Path) -> Option<Client> {
        if PathBuf::from(client.client_id.clone() + ".yml") != file.file_name()? {
            error!(client = client.client_id,
                expected_filename = client.client_id.clone() + ".yml",
                actual_filename = ?file,
                "client is stored in wrong file",
            );
            return None;
        }

        Some(client)
    }

    fn log_single_refresh(name: &str) {
        info!(client = name, "client refreshed");
    }

    fn log_single_remove(name: &str) {
        info!(client = name, "client removed");
    }
}

impl DataExt for Scope {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn validate(scope: Scope, file: &Path) -> Option<Scope> {
        let pattern = Regex::new(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
            .map_err(|e| {
                error!(%e, "scope validation regex is invalid. Please report a bug");
                e
            })
            .ok()?;
        if !pattern.is_match(&scope.name) {
            error!(name = scope.name, "Invalid scope");
            return None;
        }

        if PathBuf::from(scope.name.clone() + ".yml") != file.file_name()? {
            error!(scope = scope.name,
                expected_filename = scope.name.clone() + ".yml",
                actual_filename = ?file,
                "scope is stored in wrong file",
            );
            return None;
        }
        Some(scope)
    }

    fn log_single_refresh(name: &str) {
        info!(scope = name, "scope refreshed");
    }

    fn log_single_remove(name: &str) {
        info!(scope = name, "scope removed");
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
fn read_objects<O, T>(base: &str, transformer: T) -> Option<Vec<O>>
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
