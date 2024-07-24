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

use tera::{Context, Tera};
use tiny_auth_business::templater::{
    BindDnContext, FilledTemplate, InstantiatedTemplate, Template, TemplateError, Templater,
};
use tiny_auth_business::util::wrap_err;

pub(crate) struct BindDnTemplater(pub(crate) Template);

impl Templater for BindDnTemplater {
    type Context = BindDnContext;

    fn instantiate(&self, context: BindDnContext) -> Box<dyn FilledTemplate> {
        Box::new(FilledBindDnTemplate(self.0.clone(), context))
    }
}

struct FilledBindDnTemplate(Template, BindDnContext);

impl FilledTemplate for FilledBindDnTemplate {
    fn render(&self) -> Result<InstantiatedTemplate, TemplateError> {
        let mut context = Context::new();
        context.insert("user", &self.1.user);
        let result = Tera::one_off(
            &<Template as Into<String>>::into(self.0.clone()),
            &context,
            false,
        )
        .map_err(wrap_err)?;
        Ok(self.wrap(result))
    }
}
