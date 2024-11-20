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

use crate::authenticate::{Authenticator, AuthenticatorDispatcher};
use crate::connect::Connector;
use crate::lookup::client_lookup::{ClientLookup, ClientRepresentation};
use crate::lookup::user_lookup::{UserLookup, UserRepresentation};
use async_trait::async_trait;
use futures::future::OptionFuture;
use ldap3::{ldap_escape, Ldap};
use tiny_auth_business::client::Client;
use tiny_auth_business::client::Error as ClientError;
use tiny_auth_business::password::Error as PasswordError;
use tiny_auth_business::password::Password;
use tiny_auth_business::store::{ClientStore, PasswordConstructionError, PasswordStore, UserStore};
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;
use tracing::{error, instrument, warn};

pub struct LdapStore {
    pub(crate) name: String,
    pub(crate) connector: Connector,
    pub(crate) authenticator: AuthenticatorDispatcher,
    pub(crate) user_lookup: Option<UserLookup>,
    pub(crate) client_lookup: Option<ClientLookup>,
}

#[async_trait]
impl UserStore for LdapStore {
    #[instrument(skip_all, fields(store = self.name))]
    async fn get(&self, username: &str) -> Result<User, UserError> {
        let username = ldap_escape(username).into_owned();
        let user_lookup = self.user_lookup.as_ref().ok_or(UserError::NotFound)?;
        match user_lookup.get_cached(&username).await {
            UserRepresentation::CachedUser(cached_user) => {
                return Ok(cached_user.1);
            }
            UserRepresentation::Missing => {
                return Err(UserError::NotFound);
            }
            _ => {}
        };

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let search_entry = match self
            .authenticator
            .get_ldap_record(&mut ldap, &username)
            .await
        {
            Ok(v) => v,
            Err(UserError::NotFound) => {
                user_lookup.record_missing(&username).await;
                return Err(UserError::NotFound);
            }
            e => e.map_err(wrap_err)?,
        };
        let user = user_lookup.map_to_user(&username, search_entry).await;
        Ok(user)
    }
}

#[async_trait]
impl PasswordStore for LdapStore {
    #[instrument(name = "verify_password", skip_all, fields(store = self.name))]
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, PasswordError> {
        let username = ldap_escape(username).into_owned();
        match stored_password {
            Password::Ldap { name } => {
                if name != &self.name {
                    error!(
                        my_name = self.name,
                        password_name = name,
                        "password store dispatch bug"
                    );
                    return Err(PasswordError::BackendError);
                }
            }
            _ => {
                error!("password store dispatch bug");
                return Err(PasswordError::BackendError);
            }
        }

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let user =
            match OptionFuture::from(self.user_lookup.as_ref().map(|v| v.get_cached(&username)))
                .await
            {
                None | Some(UserRepresentation::Name(_)) => {
                    self.try_to_cache_user(&mut ldap, &username).await
                }
                Some(v @ UserRepresentation::CachedUser(_)) => v,
                Some(UserRepresentation::Missing) => {
                    warn!("tried to verify password of unknown user to this store");
                    return Err(PasswordError::BackendError);
                }
            };

        self.authenticator
            .authenticate(&mut ldap, user, password_to_check)
            .await
    }

    async fn construct_password(
        &self,
        user: User,
        _: &str,
    ) -> Result<Password, PasswordConstructionError> {
        warn!("LDAP passwords cannot be changed");
        Err(PasswordConstructionError::PasswordUnchanged(user.password))
    }
}

impl LdapStore {
    async fn try_to_cache_user<'a>(
        &self,
        ldap: &mut Ldap,
        username: &'a str,
    ) -> UserRepresentation<'a> {
        match self.authenticator.get_ldap_record(ldap, username).await {
            Ok(search_result) => {
                let user_lookup = match self.user_lookup.as_ref() {
                    None => {
                        return UserRepresentation::Name(username);
                    }
                    Some(v) => v,
                };
                UserRepresentation::CachedUser((
                    search_result.dn.clone(),
                    user_lookup.map_to_user(username, search_result).await,
                ))
            }
            Err(_) => UserRepresentation::Name(username),
        }
    }
}

#[async_trait]
impl ClientStore for LdapStore {
    #[instrument(skip_all, fields(store = self.name))]
    async fn get(&self, key: &str) -> Result<Client, ClientError> {
        let client_id = ldap_escape(key).into_owned();
        let client_lookup = self.client_lookup.as_ref().ok_or(ClientError::NotFound)?;
        match client_lookup.get_cached(&client_id).await {
            ClientRepresentation::CachedClient(cached_client) => {
                return Ok(cached_client.1);
            }
            ClientRepresentation::Missing => {
                return Err(ClientError::NotFound);
            }
            _ => {}
        };

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let search_entry = match self
            .authenticator
            .get_ldap_record(&mut ldap, &client_id)
            .await
        {
            Ok(v) => v,
            Err(UserError::NotFound) => {
                client_lookup.record_missing(key).await;
                return Err(ClientError::NotFound);
            }
            e => e.map_err(wrap_err)?,
        };
        let client = client_lookup.map_to_client(&client_id, search_entry).await;
        Ok(client)
    }
}
