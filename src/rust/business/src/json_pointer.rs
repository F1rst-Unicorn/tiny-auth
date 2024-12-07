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
use serde_derive::Deserialize;
use serde_json::{Map, Value};

const ENCODED_TILDE: &str = "~0";
const ENCODED_SLASH: &str = "~1";

pub struct ArrayAccess(pub usize);
pub struct PastLastArrayElement;

impl TryFrom<&str> for ArrayAccess {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse::<usize>().map(Self).map_err(|_| ())
    }
}

impl TryFrom<&str> for PastLastArrayElement {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Some(value).filter(|v| *v == "-").map(|_| Self).ok_or(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub struct JsonPointer {
    tokens: Vec<String>,
}

impl JsonPointer {
    pub fn pop_first(&self) -> Self {
        Self {
            tokens: self.tokens.clone().into_iter().skip(1).collect(),
        }
    }

    pub fn first(&self) -> Option<&str> {
        self.tokens.first().map(String::as_str)
    }

    pub fn construct_json(&self) -> Value {
        match self.first() {
            None => Value::Null,
            Some(token) => {
                let nested = self.pop_first().construct_json();
                if PastLastArrayElement::try_from(token).is_ok() {
                    vec![nested].into()
                } else if let Ok(ArrayAccess(index)) = ArrayAccess::try_from(token) {
                    let mut result = vec![Value::Null; index + 1];
                    result[index] = nested;
                    result.into()
                } else if token.is_empty() {
                    Value::Null
                } else {
                    let mut result = Map::new();
                    result.insert(token.to_owned(), nested);
                    result.into()
                }
            }
        }
    }
}

impl AsRef<[String]> for JsonPointer {
    fn as_ref(&self) -> &[String] {
        self.tokens.as_slice()
    }
}

impl TryFrom<String> for JsonPointer {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for JsonPointer {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.starts_with('/') {
            return Err("json pointer must start with a /");
        }

        let tokens = value
            .split('/')
            .skip(1)
            .map(String::from)
            .map(|token| token.replace(ENCODED_SLASH, "/"))
            .map(|token| token.replace(ENCODED_TILDE, "~"))
            .collect();
        Ok(Self { tokens })
    }
}

impl From<JsonPointer> for String {
    fn from(value: JsonPointer) -> Self {
        value
            .tokens
            .iter()
            .map(String::from)
            .map(|token| token.replace("~", ENCODED_TILDE))
            .map(|token| token.replace("/", ENCODED_SLASH))
            .map(|token| "/".to_owned() + &token)
            .collect::<Vec<String>>()
            .join("")
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use test_log::test;

    #[test]
    pub fn decoding_matches_encoding() {
        assert_identity("/");
        assert_identity("/name");
        assert_identity("/1");
        assert_identity("/value/1");
        assert_identity("/1/value");
        assert_identity("/~0");
        assert_identity("/~1");
        assert_identity("/~1~0");
        assert_identity("/~0~1");
        assert_identity("/~01");
        assert_identity("/~10");
    }

    fn assert_identity(json_pointer: &str) {
        assert_eq!(
            json_pointer,
            String::from(JsonPointer::try_from(json_pointer).unwrap())
        );
    }

    #[test]
    pub fn assert_tokens_are_extracted() {
        let uut = JsonPointer::try_from("/name/value/1/2/3/key/id").unwrap();

        assert_eq!(
            &vec![
                String::from("name"),
                String::from("value"),
                String::from("1"),
                String::from("2"),
                String::from("3"),
                String::from("key"),
                String::from("id"),
            ],
            uut.as_ref()
        )
    }

    #[test]
    pub fn escapes_are_handled_correctly() {
        let uut = JsonPointer::try_from("/~0/~1/~1~0/~0~1/~01/~10").unwrap();

        assert_eq!(
            &vec![
                String::from("~"),
                String::from("/"),
                String::from("/~"),
                String::from("~/"),
                String::from("~1"),
                String::from("/0"),
            ],
            uut.as_ref()
        )
    }

    #[test]
    pub fn missing_leading_slash_is_reported() {
        let uut = JsonPointer::try_from("name");

        assert!(uut.is_err());
    }

    #[test]
    pub fn slash_creates_null() {
        let uut = JsonPointer::try_from("/").unwrap();

        assert_eq!(json!(null), uut.construct_json());
    }

    #[test]
    pub fn past_last_index_creates_array_of_null() {
        let uut = JsonPointer::try_from("/-").unwrap();

        assert_eq!(json!([null]), uut.construct_json());
    }

    #[test]
    pub fn array_index_creates_array_of_nulls() {
        let uut = JsonPointer::try_from("/3").unwrap();

        assert_eq!(json!([null, null, null, null]), uut.construct_json());
    }

    #[test]
    pub fn object_key_creates_object_with_null_value() {
        let uut = JsonPointer::try_from("/key").unwrap();

        assert_eq!(json!({"key": null}), uut.construct_json());
    }
}