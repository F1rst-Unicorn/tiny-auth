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

use crate::tera::{BindDnTemplater, LdapSearchTemplater, ScopeTemplater};
use crate::web::{
    AuthenticateTemplater, AuthorizeTemplater, ConsentTemplater, WebappRootTemplater,
};
use std::sync::Arc;
use tera::Tera;
use tiny_auth_business::template::ldap_search::LdapSearchContext;
use tiny_auth_business::template::scope::ScopeContext;
use tiny_auth_business::template::web::{
    AuthenticateContext, ConsentContext, WebTemplater, WebappRootContext,
};
use tiny_auth_business::template::{bind_dn::BindDnContext, Templater};

pub fn bind_dn_templater(template: &str) -> Arc<dyn Templater<BindDnContext>> {
    Arc::new(BindDnTemplater(template.to_string().into()))
}

pub fn ldap_search_templater(template: &str) -> Arc<dyn Templater<LdapSearchContext>> {
    Arc::new(LdapSearchTemplater(template.to_string().into()))
}

pub fn scope_templater() -> Arc<dyn for<'a> Templater<ScopeContext<'a>>> {
    Arc::new(ScopeTemplater)
}

pub fn webapp_templater(tera: Arc<Tera>) -> Arc<dyn WebTemplater<WebappRootContext>> {
    Arc::new(WebappRootTemplater(tera))
}

pub fn authorize_templater(tera: Arc<Tera>) -> Arc<dyn WebTemplater<()>> {
    Arc::new(AuthorizeTemplater(tera))
}

pub fn authenticate_templater(tera: Arc<Tera>) -> Arc<dyn WebTemplater<AuthenticateContext>> {
    Arc::new(AuthenticateTemplater(tera))
}

pub fn consent_templater(tera: Arc<Tera>) -> Arc<dyn WebTemplater<ConsentContext>> {
    Arc::new(ConsentTemplater(tera))
}
