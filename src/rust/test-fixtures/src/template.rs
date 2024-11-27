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

use tiny_auth_business::template::web::{ErrorPage, WebTemplater};
use tiny_auth_business::template::{InstantiatedTemplate, TemplateError, Templater};

#[derive(Default)]
pub struct TestTemplater;

impl<T: Send + Sync> Templater<T> for TestTemplater {
    fn instantiate_by_name(
        &self,
        _context: T,
        _name: &str,
        content: &str,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        Ok(InstantiatedTemplate(content.to_owned()))
    }

    fn instantiate(&self, _context: T) -> Result<InstantiatedTemplate, TemplateError> {
        Ok(InstantiatedTemplate("".to_owned()))
    }
}

impl<T: Send + Sync> WebTemplater<T> for TestTemplater {
    fn instantiate_error_page(&self, error: ErrorPage) -> InstantiatedTemplate {
        InstantiatedTemplate(error.title().to_owned())
    }
}
