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
use serde_json::{json, Value};
use std::sync::Arc;
use tiny_auth_business::data::scope::template;
use tiny_auth_test_fixtures::data::client::CONFIDENTIAL_CLIENT;
use tiny_auth_test_fixtures::data::user::USER_1;
use tiny_auth_test_fixtures::template::TestTemplater;

#[test]
pub fn objects_are_templated() {
    let value = json!({"key": "john"});

    let (result, errors) = template(
        Arc::new(TestTemplater),
        &value,
        &USER_1,
        &CONFIDENTIAL_CLIENT,
    );

    assert!(errors.is_empty());
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(json!({"key": "john"}), result);
}

#[test]
pub fn arrays_are_templated() {
    let value = json!(["john"]);

    let (result, errors) = template(
        Arc::new(TestTemplater),
        &value,
        &USER_1,
        &CONFIDENTIAL_CLIENT,
    );

    assert!(errors.is_empty());
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(json!(["john"]), result);
}

#[test]
pub fn strings_are_templated() {
    let value = Value::String("john".to_owned());

    let (result, errors) = template(
        Arc::new(TestTemplater),
        &value,
        &USER_1,
        &CONFIDENTIAL_CLIENT,
    );

    assert!(errors.is_empty());
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(Value::String("john".to_owned()), result);
}
