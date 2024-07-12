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
use ldap3::ldap_escape;
use log::error;
use tiny_auth_business::client::Client;
use tiny_auth_business::client::Error as ClientError;
use tiny_auth_business::password::{Error, Password};
use tiny_auth_business::store::{ClientStore, PasswordStore, UserStore};
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::user::User;
use tiny_auth_business::util::wrap_err;

pub struct LdapStore {
    pub(crate) name: String,
    pub(crate) connector: Connector,
    pub(crate) authenticator: AuthenticatorDispatcher,
    pub(crate) user_lookup: Option<UserLookup>,
    pub(crate) client_lookup: Option<ClientLookup>,
}

#[async_trait]
impl UserStore for LdapStore {
    async fn get(&self, username: &str) -> Result<User, UserError> {
        let username = ldap_escape(username).into_owned();
        let user_lookup = self.user_lookup.as_ref().ok_or(UserError::NotFound)?;
        if let UserRepresentation::CachedUser(cached_user) = user_lookup.get_cached(&username).await
        {
            return Ok(cached_user.1);
        }

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let search_entry = self
            .authenticator
            .get_ldap_record(&mut ldap, &username)
            .await?;
        let user = user_lookup.map_to_user(&username, search_entry).await;
        Ok(user)
    }
}

#[async_trait]
impl PasswordStore for LdapStore {
    async fn verify(
        &self,
        username: &str,
        stored_password: &Password,
        password_to_check: &str,
    ) -> Result<bool, Error> {
        let username = ldap_escape(username).into_owned();
        match stored_password {
            Password::Ldap { name } => {
                if name != &self.name {
                    error!(
                        "Password store dispatch bug. Password names {} but this is {}",
                        name, self.name
                    );
                    return Err(Error::BackendError);
                }
            }
            _ => {
                error!("Password store dispatch bug");
            }
        }

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let user = OptionFuture::from(self.user_lookup.as_ref().map(|v| v.get_cached(&username)))
            .await
            .unwrap_or(UserRepresentation::Name(&username));
        self.authenticator
            .authenticate(&mut ldap, user, password_to_check)
            .await
    }
}

#[async_trait]
impl ClientStore for LdapStore {
    async fn get(&self, key: &str) -> Result<Client, ClientError> {
        let client_id = ldap_escape(key).into_owned();
        let client_lookup = self.client_lookup.as_ref().ok_or(ClientError::NotFound)?;
        if let ClientRepresentation::CachedClient(cached_client) =
            client_lookup.get_cached(&client_id).await
        {
            return Ok(cached_client.1);
        }

        let mut ldap = self.connector.connect().await.map_err(wrap_err)?;
        let search_entry = self
            .authenticator
            .get_ldap_record(&mut ldap, &client_id)
            .await
            .map_err(wrap_err)?;
        let client = client_lookup.map_to_client(&client_id, search_entry).await;
        Ok(client)
    }
}
