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

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Template(String);

impl From<String> for Template {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<InstantiatedTemplate> for String {
    fn from(value: InstantiatedTemplate) -> Self {
        value.0
    }
}

impl AsRef<str> for Template {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstantiatedTemplate(pub String);

impl AsRef<str> for InstantiatedTemplate {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Error, Debug, Clone)]
pub enum TemplateError {
    #[error("failed to render: {0}")]
    RenderError(String),
}

pub trait Templater<Context: Send + Sync>: Send + Sync {
    fn instantiate_by_name(
        &self,
        context: Context,
        _name: &str,
        _content: &str,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        self.instantiate(context)
    }

    fn instantiate(&self, context: Context) -> Result<InstantiatedTemplate, TemplateError>;
}
