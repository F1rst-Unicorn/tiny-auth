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
use std::error::Error;
use tera::{Context, Tera};
use tiny_auth_business::template::ldap_search::LdapSearchContext;
use tiny_auth_business::template::scope::ScopeContext;
use tiny_auth_business::template::{
    bind_dn::BindDnContext, InstantiatedTemplate, Template, TemplateError, Templater,
};

pub(crate) struct BindDnTemplater(pub(crate) Template);

impl Templater<BindDnContext> for BindDnTemplater {
    fn instantiate(&self, context: BindDnContext) -> Result<InstantiatedTemplate, TemplateError> {
        let mut tera_context = Context::new();
        tera_context.insert("user", &context.user);
        let result = Tera::one_off(self.0.as_ref(), &tera_context, false).map_err(map_err)?;
        Ok(InstantiatedTemplate(result))
    }
}

pub(crate) struct LdapSearchTemplater(pub(crate) Template);

impl Templater<LdapSearchContext> for LdapSearchTemplater {
    fn instantiate(
        &self,
        context: LdapSearchContext,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        let mut tera_context = Context::new();
        tera_context.insert("user", &context.user);
        let result = Tera::one_off(self.0.as_ref(), &tera_context, false).map_err(map_err)?;
        Ok(InstantiatedTemplate(result))
    }
}

pub(crate) struct ScopeTemplater;

impl<'a> Templater<ScopeContext<'a>> for ScopeTemplater {
    fn instantiate_by_name(
        &self,
        context: ScopeContext<'a>,
        name: &str,
        content: &str,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        let mut tera = Tera::default();
        tera.add_raw_template(name, content).map_err(map_err)?;
        let mut tera_context = Context::new();
        tera_context.insert("user", context.user);
        tera_context.insert("client", context.client);
        let result = tera.render(name, &tera_context).map_err(map_err)?;
        Ok(InstantiatedTemplate(result))
    }

    fn instantiate(
        &self,
        _context: ScopeContext<'a>,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        Ok(InstantiatedTemplate(String::default()))
    }
}

fn map_err(e: tera::Error) -> TemplateError {
    TemplateError::RenderError(render_tera_error(&e))
}

fn render_tera_error(error: &tera::Error) -> String {
    let mut result = String::new();
    result += &format!("{}", error);
    let mut source = error.source();
    while let Some(error) = source {
        result += &format!(": {}", error);
        source = error.source();
    }
    result
}
