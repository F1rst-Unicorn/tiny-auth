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
use crate::client::Client;
use crate::template::scope::ScopeContext;
use crate::template::{TemplateError, Templater};
use crate::token::{Access, Id, TokenType, Userinfo};
use crate::user::User;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use serde_json::Map;
use serde_json::Value;
use std::any::{type_name, TypeId};
use std::cmp::Ord;
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};
use tracing::{error, instrument};

#[derive(Clone, Deserialize, Debug)]
pub struct Scope {
    pub name: String,

    #[serde(rename = "pretty name")]
    pretty_name: String,

    description: String,

    mappings: Vec<Mapping>,
}

impl PartialEq for Scope {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl Eq for Scope {}

impl PartialOrd for Scope {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scope {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

pub fn parse_scope_names(names: &str) -> Vec<String> {
    names.split(' ').map(str::to_string).collect()
}

#[derive(Serialize)]
pub struct ScopeDescription {
    name: String,

    pretty_name: String,

    description: String,
}

impl From<Scope> for ScopeDescription {
    fn from(s: Scope) -> Self {
        Self {
            name: s.name,
            pretty_name: s.pretty_name,
            description: s.description,
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("template error")]
    TemplateError,

    #[error("attribute selection error")]
    AttributeSelectionError,

    #[error("failed to merge attributes: {0}")]
    MergeError(#[from] MergeError),

    #[error("serialisation error: {0}")]
    SerialisationError(#[from] serde_json::Error),
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

    #[instrument(level = "debug", skip(templater, user, client, self), fields(scope = self.name, ?destination))]
    pub fn generate_claims<'a>(
        &self,
        templater: Arc<dyn Templater<ScopeContext<'a>>>,
        user: &'a User,
        client: &'a Client,
        destination: Destination,
    ) -> Result<Value, Error> {
        let mut result = Map::new();
        for m in self
            .mappings
            .iter()
            .filter(|v| v.destination.contains(&destination))
        {
            let claims = m.generate_claims(templater.clone(), user, client)?;
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
    #[serde(with = "serde_yaml::with::singleton_map")]
    mapping_type: Type,

    #[serde(default)]
    optional: bool,

    #[serde(default = "default_destination")]
    destination: BTreeSet<Destination>,
}

fn default_destination() -> BTreeSet<Destination> {
    BTreeSet::from_iter(
        vec![
            Destination::AccessToken,
            Destination::IdToken,
            Destination::UserInfo,
        ]
        .into_iter(),
    )
}

#[derive(Clone, Deserialize, Debug, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Destination {
    #[serde(alias = "access_token")]
    #[serde(alias = "access token")]
    #[serde(alias = "accesstoken")]
    #[serde(alias = "access")]
    AccessToken,
    #[serde(alias = "id_token")]
    #[serde(alias = "id token")]
    #[serde(alias = "idtoken")]
    #[serde(alias = "id")]
    IdToken,
    #[serde(alias = "user_info")]
    #[serde(alias = "user info")]
    #[serde(alias = "userinfo")]
    UserInfo,
}

impl<T: TokenType + 'static> From<T> for Destination {
    fn from(_: T) -> Self {
        if TypeId::of::<T>() == TypeId::of::<Access>() {
            Self::AccessToken
        } else if TypeId::of::<T>() == TypeId::of::<Userinfo>() {
            Self::UserInfo
        } else if TypeId::of::<T>() == TypeId::of::<Id>() {
            Self::IdToken
        } else {
            error!(typename = %type_name::<T>(), "missing destination type, returning default");
            Self::AccessToken
        }
    }
}

impl Mapping {
    fn generate_claims<'a>(
        &self,
        templater: Arc<dyn Templater<ScopeContext<'a>>>,
        user: &'a User,
        client: &'a Client,
    ) -> Result<Value, Error> {
        match &self.mapping_type {
            Type::Plain => Ok(self.structure.clone()),
            Type::Template => {
                let (value, errors) = template(templater, &self.structure, user, client);
                if !errors.is_empty() {
                    if self.optional {
                        debug!("failed to template optional claims:");
                        for e in errors {
                            debug!("{}", &e);
                        }
                        Ok(value.unwrap_or_else(|| Value::Object(Map::new())))
                    } else {
                        warn!("failed to template claims:");
                        for e in errors {
                            debug!("{}", &e);
                        }
                        Err(Error::TemplateError)
                    }
                } else {
                    Ok(value.unwrap_or_else(|| Value::Object(Map::new())))
                }
            }
            Type::UserAttribute(selector) => {
                let value = serde_json::to_value(user).map_err(Error::from)?;
                let value_to_copy = copy_values(value, selector.clone(), &mut Vec::new())?;
                insert_value(self.structure.clone(), value_to_copy)
            }
            Type::ClientAttribute(selector) => {
                let value = serde_json::to_value(client).map_err(Error::from)?;
                let value_to_copy = copy_values(value, selector.clone(), &mut Vec::new())?;
                insert_value(self.structure.clone(), value_to_copy)
            }
        }
    }
}

fn insert_value(structure: Value, value: Value) -> Result<Value, Error> {
    match structure {
        Value::Null => Ok(value),
        Value::Object(mut map) => {
            if map.len() != 1 {
                error!("Exactly one attribute is allowed in selectors. Use 'null' to terminate your selector");
                return Err(Error::AttributeSelectionError);
            }
            let key = map.keys().next().unwrap().clone();
            match map.remove(&key) {
                Some(Value::Null) => {
                    map.insert(key, value);
                    Ok(Value::Object(map))
                }
                Some(u) => {
                    let result = insert_value(u, value)?;
                    map.insert(key, result);
                    Ok(Value::Object(map))
                }
                None => unreachable!("checked before"),
            }
        }
        _ => {
            error!("structure may only contain dicts with exactly one key");
            Err(Error::AttributeSelectionError)
        }
    }
}

fn copy_values(value: Value, selector: Value, path: &mut Vec<String>) -> Result<Value, Error> {
    match (value, selector) {
        (Value::Object(mut value), Value::Object(mut map)) => {
            if map.len() != 1 {
                error!("Exactly one attribute is allowed in selectors. Use 'null' to terminate your selector");
                return Err(Error::AttributeSelectionError);
            }
            let k = map.keys().next().unwrap().clone();
            let v = map.remove(&k).unwrap();
            let current_value = match value.remove(&k) {
                None => {
                    path.push(k);
                    error!(attribute = path.join(" -> "), "not found");
                    path.pop();
                    return Err(Error::AttributeSelectionError);
                }
                Some(v) => v,
            };
            match v {
                Value::Null => {
                    let mut map = Map::new();
                    map.insert(k, current_value);
                    Ok(Value::Object(map))
                }
                v @ Value::Object(_) => {
                    path.push(k);
                    let result_value = copy_values(current_value, v, path)?;
                    Ok(result_value)
                }
                _ => {
                    error!("Use 'null' to terminate your selector. Only dict keys are allowed in selectors");
                    Err(Error::AttributeSelectionError)
                }
            }
        }
        (v, Value::Null) => Ok(v),
        _ => Err(Error::AttributeSelectionError),
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

fn template<'a>(
    templater: Arc<dyn Templater<ScopeContext<'a>>>,
    value: &Value,
    user: &'a User,
    client: &'a Client,
) -> (Option<Value>, Vec<TemplateError>) {
    let context = ScopeContext { user, client };
    template_internally(value, &mut Default::default(), context, templater)
}

fn template_internally<'a>(
    value: &Value,
    path: &mut Vec<String>,
    context: ScopeContext<'a>,
    templater: Arc<dyn Templater<ScopeContext<'a>>>,
) -> (Option<Value>, Vec<TemplateError>) {
    match value {
        Value::String(template) => {
            let path = path.join(".");
            match templater.instantiate_by_name(context, &path, template) {
                Ok(result) => (Some(result.as_ref().into()), Vec::new()),
                Err(e) => (None, vec![e]),
            }
        }
        Value::Array(array) => {
            let mut values = Vec::new();
            let mut errors = Vec::new();
            for (i, v) in array.iter().enumerate() {
                path.push(format!("{}", i));
                let result = template_internally(v, path, context, templater.clone());
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
                let result = template_internally(v, path, context, templater.clone());
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

#[derive(Debug, PartialEq, Eq, Error)]
pub enum MergeError {
    #[error("type mismatch")]
    TypeMismatch,

    #[error("types are not mergable, one is not a collection")]
    UnmergableTypes,
}

pub fn merge(left: Value, right: Value) -> Result<Value, MergeError> {
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
    use crate::client::tests::get_test_client;
    use crate::user::tests::get_test_user;

    use crate::template::test_fixtures::TestTemplater;

    use serde_json::json;

    #[test]
    pub fn valid_inserting_works() {
        let structure = json!({
            "key": {
                "key": null
            }
        });
        let expected = json!({
            "key": {
                "key": 4
            }
        });

        let result = insert_value(structure, json!(4));

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(expected, result);
    }

    #[test]
    pub fn inserting_to_null_returns_value() {
        let result = insert_value(json!(null), json!(4));

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(json!(4), result);
    }

    #[test]
    pub fn inserting_to_array_fails() {
        let result = insert_value(json!({}), json!(null));

        assert!(result.is_err());
        if let Error::AttributeSelectionError = result.unwrap_err() {
        } else {
            unreachable!();
        }
    }

    #[test]
    pub fn valid_copying_works() {
        let selector = json!({
            "key": {
                "key": null,
            }
        });
        let value = json!({
            "key": {
                "key": "value",
            }
        });

        let result = copy_values(value, selector, &mut Vec::new());

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(json!({"key": "value"}), result);
    }

    #[test]
    pub fn copying_with_unterminated_selector_gives_error() {
        let selector = json!({
            "key": {
                "key": 1,
            }
        });
        let value = json!({
            "key": {
                "key": "value",
            }
        });

        let result = copy_values(value, selector, &mut Vec::new());

        assert!(result.is_err());
        if let Error::AttributeSelectionError = result.unwrap_err() {
        } else {
            unreachable!();
        }
    }

    #[test]
    pub fn copying_with_unknown_attribute_gives_error() {
        let selector = json!({
            "key": {
                "key": null,
            }
        });
        let value = json!({
            "key": {
                "other_name": null,
            }
        });

        let result = copy_values(value, selector, &mut Vec::new());

        assert!(result.is_err());
        if let Error::AttributeSelectionError = result.unwrap_err() {
        } else {
            unreachable!();
        }
    }

    #[test]
    pub fn copying_with_invalid_selector_gives_error() {
        let selector = json!({
            "key": {
                "key": null,
                "invalid_second_key": null
            }
        });
        let value = json!({
            "key": {
                "key": null,
                "invalid_second_key": null
            }
        });

        let result = copy_values(value, selector, &mut Vec::new());

        assert!(result.is_err());
        if let Error::AttributeSelectionError = result.unwrap_err() {
        } else {
            unreachable!();
        }
    }

    #[test]
    pub fn copying_with_invalid_types_gives_error() {
        let result = copy_values(json!(false), json!(false), &mut Vec::new());

        assert!(result.is_err());
        if let Error::AttributeSelectionError = result.unwrap_err() {
        } else {
            unreachable!();
        }
    }

    #[test]
    pub fn copying_with_null_selector_returns_value() {
        let result = copy_values(json!(false), json!(null), &mut Vec::new());

        assert!(result.is_ok());
        assert_eq!(json!(false), result.unwrap());
    }

    #[test]
    pub fn objects_are_templated() {
        let user = get_test_user();
        let client = get_test_client();
        let value = json!({"key": "john"});

        let (result, errors) = template(Arc::new(TestTemplater), &value, &user, &client);

        assert!(errors.is_empty());
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(json!({"key": "john"}), result);
    }

    #[test]
    pub fn arrays_are_templated() {
        let user = get_test_user();
        let client = get_test_client();
        let value = json!(["john"]);

        let (result, errors) = template(Arc::new(TestTemplater), &value, &user, &client);

        assert!(errors.is_empty());
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(json!(["john"]), result);
    }

    #[test]
    pub fn strings_are_templated() {
        let user = get_test_user();
        let client = get_test_client();
        let value = Value::String("john".to_string());

        let (result, errors) = template(Arc::new(TestTemplater), &value, &user, &client);

        assert!(errors.is_empty());
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(Value::String("john".to_string()), result);
    }

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
    pub fn merging_objects_with_overlapping_keys_fails() {
        let mut first = Map::new();
        first.insert("key".to_string(), Value::String("first".to_string()));
        let mut second = Map::new();
        second.insert("key".to_string(), Value::String("second".to_string()));

        let result = merge(Value::Object(first), Value::Object(second));

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(MergeError::UnmergableTypes, result);
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
