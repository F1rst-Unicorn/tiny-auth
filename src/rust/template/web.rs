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

use crate::tera::{map_err, render_tera_error};
use std::collections::HashMap;
use std::sync::Arc;
use tera::to_value;
use tera::Result as TeraResult;
use tera::Tera;
use tera::Value;
use tera::{from_value, Context};
use tiny_auth_business::template::web::{
    AuthenticateContext, AuthenticateError, ConsentContext, ErrorPage, WebTemplater,
    WebappRootContext,
};
use tiny_auth_business::template::{InstantiatedTemplate, TemplateError, Templater};
use tracing::{error, instrument, span, trace, warn, Level};

pub(crate) struct WebappRootTemplater(pub(crate) Arc<Tera>);

impl Templater<WebappRootContext> for WebappRootTemplater {
    fn instantiate(
        &self,
        context: WebappRootContext,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        let mut tera_context = Context::new();
        tera_context.insert("tiny_auth_provider_url", &context.provider_url);
        tera_context.insert("tiny_auth_api_url", &context.api_url);
        tera_context.insert("tiny_auth_web_base", &context.web_base);
        Ok(InstantiatedTemplate(
            self.0
                .render("index.html.j2", &tera_context)
                .map_err(map_err)?,
        ))
    }
}

impl WebTemplater<WebappRootContext> for WebappRootTemplater {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate {
        render_error_page(&self.0, error)
    }
}

pub(crate) struct AuthorizeTemplater(pub(crate) Arc<Tera>);

impl Templater<()> for AuthorizeTemplater {
    fn instantiate(&self, _context: ()) -> Result<InstantiatedTemplate, TemplateError> {
        error!("no call expected");
        Ok(InstantiatedTemplate("".to_owned()))
    }
}

impl WebTemplater<()> for AuthorizeTemplater {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate {
        render_error_page(&self.0, error)
    }
}

pub(crate) struct AuthenticateTemplater(pub(crate) Arc<Tera>);

impl Templater<AuthenticateContext> for AuthenticateTemplater {
    fn instantiate(
        &self,
        context: AuthenticateContext,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        let mut tera_context = Context::new();
        tera_context.insert(
            "error",
            &context
                .error
                .as_ref()
                .map(AuthenticateError::message)
                .unwrap_or(""),
        );
        tera_context.insert("tries", &context.tries_left);
        tera_context.insert("login_hint", &context.login_hint);
        tera_context.insert("csrftoken", &context.csrf_token);
        Ok(InstantiatedTemplate(
            self.0
                .render("authenticate.html.j2", &tera_context)
                .map_err(map_err)?,
        ))
    }
}

impl WebTemplater<AuthenticateContext> for AuthenticateTemplater {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate {
        render_error_page(&self.0, error)
    }
}

pub(crate) struct ConsentTemplater(pub(crate) Arc<Tera>);

impl Templater<ConsentContext> for ConsentTemplater {
    fn instantiate(&self, context: ConsentContext) -> Result<InstantiatedTemplate, TemplateError> {
        let mut tera_context = Context::new();
        tera_context.insert("client", &context.client);
        tera_context.insert("user", &context.user);
        tera_context.insert("csrftoken", &context.csrf_token);
        tera_context.insert("scopes", &context.scopes);
        Ok(InstantiatedTemplate(
            self.0
                .render("consent.html.j2", &tera_context)
                .map_err(map_err)?,
        ))
    }
}

impl WebTemplater<ConsentContext> for ConsentTemplater {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate {
        render_error_page(&self.0, error)
    }
}

fn render_error_page(tera: &Tera, error: ErrorPage) -> InstantiatedTemplate {
    let mut context = Context::new();
    context.insert("id", error.id());
    context.insert("title", error.title());
    match tera.render("error.html.j2", &context) {
        Err(e) => {
            warn!(e = render_tera_error(&e));
            InstantiatedTemplate(error.title().to_owned())
        }
        Ok(v) => InstantiatedTemplate(v),
    }
}

pub fn load_template_engine(
    static_files_root: &str,
    http_path: &str,
) -> Result<Tera, TemplateError> {
    let template_path = static_files_root.to_owned() + "/templates/";
    let mut tera = Tera::new(&(template_path + "**/*")).map_err(map_err)?;
    tera.register_function("url", url_mapper);
    tera.register_function("translate", translator);
    tera.register_function("static", make_static_mapper(http_path.to_owned()));
    Ok(tera)
}

#[instrument(level = Level::TRACE, ret)]
fn url_mapper(args: &HashMap<String, Value>) -> TeraResult<Value> {
    match args.get("name") {
        Some(val) => Ok(val.clone()),
        None => {
            error!("no url name given");
            Err("oops".into())
        }
    }
}

#[instrument(level = Level::TRACE, ret)]
fn translator(args: &HashMap<String, Value>) -> TeraResult<Value> {
    match args.get("term") {
        Some(val) => Ok(val.clone()),
        None => {
            error!("no term given");
            Err("oops".into())
        }
    }
}

#[allow(clippy::type_complexity)]
fn make_static_mapper(
    http_path: String,
) -> Box<dyn Fn(&HashMap<String, Value>) -> TeraResult<Value> + Sync + Send> {
    Box::new(move |args| -> TeraResult<Value> {
        let _guard = span!(Level::DEBUG, "static_mapper", ?args).entered();
        let result = match args.get("name") {
            Some(val) => match from_value::<String>(val.clone()) {
                Ok(v) => to_value(http_path.to_owned() + &v).map_err(Into::into),
                Err(e) => {
                    error!(%e, "could not convert to string");
                    Err("oops".into())
                }
            },
            None => {
                error!("no name given");
                Err("oops".into())
            }
        };
        trace!(?result);
        result
    })
}
