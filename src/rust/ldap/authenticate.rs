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
use std::sync::Arc;
use tiny_auth_business::password::Error as PasswordError;
use tiny_auth_business::template::ldap_search::LdapSearchContext;
use tiny_auth_business::template::{bind_dn::BindDnContext, Templater};
use tiny_auth_business::user::Error as UserError;
use tiny_auth_business::util::wrap_err;
use tracing::{debug, instrument, warn, Level};

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
    ) -> Result<bool, PasswordError>;

    async fn get_ldap_record(
        &self,
        ldap: &mut Ldap,
        username: &str,
    ) -> Result<SearchEntry, UserError>;

    async fn check(&self, ldap: &mut Ldap) -> bool;
}

pub(crate) struct SimpleBind {
    pub(crate) bind_dn_templates: Vec<Arc<dyn Templater<BindDnContext>>>,
}

#[async_trait]
impl Authenticator for SimpleBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, PasswordError> {
        match user {
            UserRepresentation::Name(username) => {
                for bind_template in &self.bind_dn_templates {
                    let bind_dn = bind_template
                        .instantiate(BindDnContext {
                            user: username.to_owned(),
                        })
                        .map_err(wrap_err)?;
                    if simple_bind(ldap, bind_dn.as_ref(), password)
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
            UserRepresentation::Missing => Err(wrap_err(UserError::NotFound))?,
        }
    }

    async fn get_ldap_record(&self, _: &mut Ldap, _: &str) -> Result<SearchEntry, UserError> {
        Err(UserError::NotFound)
    }

    async fn check(&self, _: &mut Ldap) -> bool {
        true
    }
}

pub(crate) struct SearchBind {
    pub(crate) bind_dn: String,
    pub(crate) bind_dn_password: String,
    pub(crate) searches: Vec<LdapSearch>,
}

pub struct LdapSearch {
    pub base_dn: String,
    pub search_filter: Arc<dyn Templater<LdapSearchContext>>,
}

#[async_trait]
impl Authenticator for SearchBind {
    async fn authenticate(
        &self,
        ldap: &mut Ldap,
        user: UserRepresentation<'_>,
        password: &str,
    ) -> Result<bool, PasswordError> {
        let dn = match user {
            UserRepresentation::Name(username) => {
                let search_entry = self
                    .get_ldap_record(ldap, username)
                    .await
                    .map_err(wrap_err)?;
                search_entry.dn
            }
            UserRepresentation::CachedUser((dn, _)) => dn,
            UserRepresentation::Missing => Err(wrap_err(UserError::NotFound))?,
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
                bind_dn = self.bind_dn,
                "wrong username or password for search bind mode",
            );
            return Err(UserError::BackendError);
        };

        for search in &self.searches {
            let filter = search
                .search_filter
                .instantiate(LdapSearchContext {
                    user: username.to_owned(),
                })
                .map_err(wrap_err)?;
            if let Some(value) = Self::search(ldap, username, &search, filter.as_ref()).await {
                return value;
            }
        }
        Err(UserError::NotFound)
    }

    async fn check(&self, ldap: &mut Ldap) -> bool {
        simple_bind(ldap, &self.bind_dn, &self.bind_dn_password)
            .await
            .is_ok()
    }
}

impl SearchBind {
    #[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(filter = filter))]
    async fn search(
        ldap: &mut Ldap,
        _username: &str,
        search: &&LdapSearch,
        filter: &str,
    ) -> Option<Result<SearchEntry, UserError>> {
        debug!(base_dn = &search.base_dn, "searching");
        let result = match ldap
            .search(&search.base_dn, Scope::Subtree, filter, &["*", "+"])
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(%e, "searching failed");
                return Some(Err(UserError::BackendErrorWithContext(Arc::new(e))));
            }
        };

        if let Some(entry) = result.0.into_iter().next() {
            let entry = SearchEntry::construct(entry);
            return Some(Ok(entry));
        }
        None
    }
}

#[instrument(level = Level::DEBUG, skip_all, name = "cid", fields(bind_dn = bind_dn))]
async fn simple_bind(ldap: &mut Ldap, bind_dn: &str, password: &str) -> Result<bool, LdapError> {
    debug!("binding to LDAP");
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
                "unexpected LDAP result code while binding: {}. {}",
                v, result.text
            );
            Err(LdapError::BindError)
        }
    }
}
