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

use crate::domain::Client;
use crate::domain::User;
use crate::util::render_tera_error;

use serde_json::Map;
use serde_json::Value;

use log::debug;
use log::error;

use tera::Context;
use tera::Tera;

use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Clone, Deserialize, Debug)]
pub struct Scope {
    pub name: String,

    #[serde(rename = "pretty name")]
    pretty_name: String,

    description: String,

    mappings: Vec<Mapping>,
}

#[derive(Serialize)]
pub struct ScopeDescription {
    pretty_name: String,

    description: String,
}

impl From<Scope> for ScopeDescription {
    fn from(s: Scope) -> Self {
        Self {
            pretty_name: s.pretty_name,
            description: s.description,
        }
    }
}

pub enum Error {
    TemplateError,

    MergeError(MergeError),
}

impl From<MergeError> for Error {
    fn from(e: MergeError) -> Self {
        Error::MergeError(e)
    }
}

impl Scope {
    pub fn new(name: &str, pretty_name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            pretty_name: pretty_name.to_string(),
            description: description.to_string(),
            mappings: Vec::new(),
        }
    }

    pub fn generate_claims(&self, user: &User, client: &Client) -> Result<Value, Error> {
        let mut result = Map::new();
        for m in &self.mappings {
            let claims = m.generate_claims(user, client)?;
            let merged = merge(Value::Object(result), claims)?;
            result = match merged {
                Value::Object(result) => result,
                _ => return Err(MergeError::TypeMismatch.into()),
            };
        }
        Ok(Value::Object(result))
    }
}

#[derive(Clone, Deserialize, Debug)]
struct Mapping {
    structure: Value,

    #[serde(rename = "type")]
    mapping_type: Type,

    #[serde(default)]
    optional: bool,
}

impl Mapping {
    fn generate_claims(&self, user: &User, client: &Client) -> Result<Value, Error> {
        match self.mapping_type {
            Type::Plain => Ok(self.structure.clone()),
            Type::Template => {
                let (value, errors) = template(&self.structure, user, client);
                if !errors.is_empty() && !self.optional {
                    error!("failed to template claims:");
                    for e in errors {
                        error!("{}", render_tera_error(&e));
                    }
                    Err(Error::TemplateError)
                } else {
                    debug!("failed to template optional claims:");
                    for e in errors {
                        debug!("{}", render_tera_error(&e));
                    }
                    Ok(value.unwrap_or_else(|| Value::Object(Map::new())))
                }
            }
            _ => todo!(),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
enum Type {
    #[serde(rename = "plain")]
    Plain,

    #[serde(rename = "template")]
    Template,

    #[serde(rename = "user_attribute")]
    UserAttribute(Value),

    #[serde(rename = "client_attribute")]
    ClientAttribute(Value),
}

fn template(value: &Value, user: &User, client: &Client) -> (Option<Value>, Vec<tera::Error>) {
    template_internally(value, &mut Default::default(), user, client)
}

fn template_internally(
    value: &Value,
    path: &mut Vec<String>,
    user: &User,
    client: &Client,
) -> (Option<Value>, Vec<tera::Error>) {
    let mut context = Context::new();
    context.insert("user", user);
    context.insert("client", client);
    let context = context;
    let mut tera = Tera::default();

    match value {
        Value::String(template) => {
            let path = path.join(".");
            if let Err(e) = tera.add_raw_template(&path, template) {
                return (None, vec![e]);
            }
            match tera.render(&path, &context) {
                Ok(result) => (Some(Value::String(result)), Vec::new()),
                Err(e) => (None, vec![e]),
            }
        }
        Value::Array(array) => {
            let mut values = Vec::new();
            let mut errors = Vec::new();
            for (i, v) in array.iter().enumerate() {
                path.push(format!("{}", i));
                let result = template_internally(v, path, user, client);
                path.pop();
                match result {
                    (None, v) => errors.extend(v),
                    (Some(value), v) => {
                        values.push(value);
                        errors.extend(v);
                    }
                }
            }
            if values.is_empty() {
                (None, errors)
            } else {
                (Some(Value::Array(values)), errors)
            }
        }
        Value::Object(members) => {
            let mut values = Map::new();
            let mut errors = Vec::new();
            for (k, v) in members {
                path.push(k.clone());
                let result = template_internally(v, path, user, client);
                path.pop();
                match result {
                    (None, e) => errors.extend(e),
                    (Some(value), e) => {
                        values.insert(k.clone(), value);
                        errors.extend(e);
                    }
                }
            }

            if values.is_empty() {
                (None, errors)
            } else {
                (Some(Value::Object(values)), errors)
            }
        }
        x => (Some(x.clone()), Vec::new()),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MergeError {
    TypeMismatch,

    UnmergableTypes,
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::TypeMismatch => write!(f, "type mismatch"),
            MergeError::UnmergableTypes => write!(f, "unmergable types"),
        }
    }
}

fn merge(left: Value, right: Value) -> Result<Value, MergeError> {
    match left {
        Value::Array(mut left) => match right {
            Value::Array(right) => {
                left.extend(right);
                Ok(Value::Array(left))
            }
            _ => Err(MergeError::TypeMismatch),
        },
        Value::Object(left) => match right {
            Value::Object(mut right) => {
                let mut result = Map::new();
                for (k, v) in left.into_iter() {
                    if right.contains_key(&k) {
                        let right_value = right.remove(&k).unwrap();
                        result.insert(k, merge(v, right_value)?);
                    } else {
                        result.insert(k, v);
                    }
                }
                for (k, v) in right {
                    result.insert(k, v);
                }
                Ok(Value::Object(result))
            }
            _ => Err(MergeError::TypeMismatch),
        },
        _ => Err(MergeError::UnmergableTypes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn two_arrays_are_merged() {
        let one = Value::Number(1.into());
        let two = Value::Number(2.into());
        let first = vec![one.clone()];
        let second = vec![two.clone()];

        let result = merge(Value::Array(first), Value::Array(second));

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, Value::Array(vec![one, two]))
    }

    #[test]
    pub fn merging_array_and_number_fails() {
        let one = Value::Number(1.into());
        let two = Value::Number(2.into());
        let first = vec![one.clone()];

        let result = merge(Value::Array(first), two.clone());

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result, MergeError::TypeMismatch);
    }

    #[test]
    pub fn merging_object_with_string_fails() {
        let first = Map::new();

        let result = merge(Value::Object(first), Value::String("".to_string()));

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result, MergeError::TypeMismatch);
    }

    #[test]
    pub fn merging_two_objects_succeeds() {
        let mut first = Map::new();
        first.insert("first".to_string(), Value::String("first".to_string()));
        let mut second = Map::new();
        second.insert("second".to_string(), Value::String("second".to_string()));

        let mut expected = Map::new();
        expected.insert("first".to_string(), Value::String("first".to_string()));
        expected.insert("second".to_string(), Value::String("second".to_string()));

        let result = merge(Value::Object(first), Value::Object(second));

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, Value::Object(expected));
    }

    #[test]
    pub fn merging_number_and_string_fails() {
        let one = Value::Number(1.into());

        let result = merge(one, Value::String(String::new()));

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result, MergeError::UnmergableTypes);
    }
}
