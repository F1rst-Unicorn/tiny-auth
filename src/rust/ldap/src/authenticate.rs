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

use crate::error::LdapError;
use crate::lookup::user_lookup::UserRepresentation;
use async_trait::async_trait;
use enum_dispatch::enum_dispatch;
use ldap3::{Ldap, Scope, SearchEntry};
use log::{debug, warn};
use std::sync::Arc;
use tera::{Context, Tera};
use tiny_auth_business::password::Error;
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::util::wrap_err;

#[enum_dispatch(Authenticator)]
pub(crate) enum AuthenticatorDispatcher {
    SimpleBind,
    SearchBind,
}

#[async_trait]
#[enum_dispatch]
pub(crate) trait Authenticator {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, Error>;

    async fn get_ldap_record(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<SearchEntry, UserError>;
}

pub(crate) struct SimpleBind {
    pub(crate) bind_dn_format: Vec<String>,
}

#[async_trait]
impl Authenticator for SimpleBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, Error> {
        match user {
            UserRepresentation::Name(username) => {
                for bind_template in &self.bind_dn_format {
                    let bind_dn = format_username(bind_template, username).map_err(wrap_err)?;
                    if simple_bind(ldap, &bind_dn, password)
                        .await
                        .map_err(wrap_err)?
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            UserRepresentation::CachedUser((dn, _)) => {
                Ok(simple_bind(ldap, &dn, password).await.map_err(wrap_err)?)
            }
        }
    }

    async fn get_ldap_record(&self, _: &mut Ldap, _: &str) -> Result<SearchEntry, UserError> {
        Err(UserError::NotFound)
    }
}

pub(crate) struct SearchBind {
    pub(crate) bind_dn: String,
    pub(crate) bind_dn_password: String,
    pub(crate) searches: Vec<LdapSearch>,
}

pub struct LdapSearch {
    pub base_dn: String,
    pub search_filter: String,
}

pub(crate) trait AttributeMapping<T>: Sync + Send {
    fn map(&self, entity: T, search_entry: &SearchEntry) -> T;
}

#[async_trait]
impl Authenticator for SearchBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, Error> {
        let dn = match user {
            UserRepresentation::Name(username) => {
                let search_entry = self
                    .get_ldap_record(ldap, username)
                    .await
                    .map_err(wrap_err)?;
                search_entry.dn
            }
            UserRepresentation::CachedUser((dn, _)) => dn,
        };
        Ok(simple_bind(ldap, &dn, password).await.map_err(wrap_err)?)
    }

    async fn get_ldap_record(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<SearchEntry, UserError> {
        if !simple_bind(ldap, &self.bind_dn, &self.bind_dn_password)
            .await
            .map_err(wrap_err)?
        {
            warn!(
                "wrong username or password for search bind mode. Username '{}'",
                self.bind_dn
            );
            return Err(UserError::BackendError);
        };

        for search in &self.searches {
            let filter = format_username(&search.search_filter, username).map_err(wrap_err)?;
            debug!("searching in {} for {}", &search.base_dn, &filter);
            let result = match ldap
                .search(&search.base_dn, Scope::Subtree, &filter, &["*", "+"])
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("searching for user '{}' failed. {}", username, e);
                    return Err(UserError::BackendErrorWithContext(Arc::new(e)));
                }
            };

            if let Some(entry) = result.0.into_iter().next() {
                let entry = SearchEntry::construct(entry);
                return Ok(entry);
            }
        }
        Err(UserError::NotFound)
    }
}

async fn simple_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> Result<bool, LdapError> {
    debug!("binding to LDAP as '{}'", bind_dn);
    let result = ldap
        .simple_bind(bind_dn, password)
        .await
        .map_err(LdapError::BindErrorWithContext)?;
    match result.rc {
        0 => Ok(true),
        49 => {
            debug!("wrong username or password");
            Ok(false)
        }
        v => {
            warn!(
                "Unexpected LDAP result code while binding: {}. {}",
                v, result.text
            );
            Err(LdapError::BindError)
        }
    }
}

fn format_username(format: &str, username: &str) -> Result<String, LdapError> {
    let mut tera = Tera::default();
    let mut context = Context::new();
    context.insert("user", username);
    tera.render_str(format, &context).map_err(|e| {
        warn!("failed to construct bind dn: {}", e);
        LdapError::FormatError(e)
    })
}
