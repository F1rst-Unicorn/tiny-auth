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
use crate::template::scope::ScopeContext;
use crate::template::{InstantiatedTemplate, TemplateError, Templater};

pub struct TestScopeTemplater;

impl<'a> Templater<ScopeContext<'a>> for TestScopeTemplater {
    fn instantiate_by_name(
        &self,
        _context: ScopeContext<'a>,
        _name: &str,
        content: &str,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        Ok(InstantiatedTemplate(content.to_string()))
    }

    fn instantiate(
        &self,
        _context: ScopeContext<'a>,
    ) -> Result<InstantiatedTemplate, TemplateError> {
        Ok(InstantiatedTemplate("".to_string()))
    }
}
