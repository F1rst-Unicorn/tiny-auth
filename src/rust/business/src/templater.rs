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

use serde::de::StdError;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Template(pub String);

impl From<Template> for String {
    fn from(value: Template) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstantiatedTemplate(pub String);

impl From<InstantiatedTemplate> for String {
    fn from(value: InstantiatedTemplate) -> Self {
        value.0
    }
}

pub trait FilledTemplate {
    fn render(&self) -> Result<InstantiatedTemplate, TemplateError>;

    fn wrap(&self, instantiated_template: String) -> InstantiatedTemplate {
        InstantiatedTemplate(instantiated_template)
    }
}

#[derive(Error, Debug, Clone)]
pub enum TemplateError {
    #[error("failed to render: {0}")]
    RenderError(#[from] Arc<dyn StdError + Send + Sync>),
}

pub trait Templater: Send + Sync {
    type Context;
    fn instantiate(&self, context: Self::Context) -> Box<dyn FilledTemplate>;
}

pub struct BindDnContext {
    pub user: String,
}
