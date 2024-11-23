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

pub mod loading {
    use crate::data_loader::Multiplicity::{ToMany, ToOne};
    use crate::data_loader::*;
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;
    use serde_json::{json, Value};
    use test_log::test;

    lazy_static! {
        static ref USER: Value = json!({
            "id": 1,
            "name": "John",
        });
        static ref DESK: Value = json!({
            "material":"steel",
        });
        static ref CAT: Value = json!({
            "type":"cat",
        });
        static ref DOG: Value = json!({
            "type":"dog",
        });
        static ref BUILDING: Value = json!({
            "street":"Lincoln Street",
        });
        static ref LARGE_ROOM: Value = json!({
            "kind":"large",
        });
        static ref SMALL_ROOM: Value = json!({
            "kind":"small",
        });
    }

    #[test]
    pub fn data_from_documentation_example_works() {
        let actual = load_user(
            vec![
                DataLoader::new("desk".to_owned(), "/user/desk".try_into().unwrap(), ToOne),
                DataLoader::new(
                    "building".to_owned(),
                    "/user/building".try_into().unwrap(),
                    ToOne,
                ),
                DataLoader::new("pets".to_owned(), "/user/pets".try_into().unwrap(), ToMany),
                DataLoader::new(
                    "meeting_rooms".to_owned(),
                    "/building/meeting_rooms".try_into().unwrap(),
                    ToMany,
                ),
            ],
            vec![
                LoadedData::new([(2, DESK.clone())], [(1, vec![2])]),
                LoadedData::new([(3, BUILDING.clone())], [(1, vec![3])]),
                LoadedData::new([(3, CAT.clone()), (4, DOG.clone())], [(1, vec![3, 4])]),
                LoadedData::new(
                    [(5, SMALL_ROOM.clone()), (6, LARGE_ROOM.clone())],
                    [(3, vec![5, 6])],
                ),
            ],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "desk": DESK.clone(),
                "building": {
                    "street":"Lincoln Street",
                    "meeting_rooms": [
                        SMALL_ROOM.clone(),
                        LARGE_ROOM.clone(),
                    ],
                },
                "pets": [
                    CAT.clone(),
                    DOG.clone(),
                ],
            }),
            actual
        );
    }

    #[test]
    pub fn missing_loaded_data_gives_null() {
        let actual = load_user(
            vec![DataLoader::new(
                "desk".to_owned(),
                "/user/desk".try_into().unwrap(),
                ToOne,
            )],
            vec![],
            USER.clone(),
            1,
        );

        assert_eq!(Value::Null, actual);
    }

    #[test]
    pub fn non_unique_data_loader_names_give_null() {
        let actual = load_user(
            vec![
                DataLoader::new("desk".to_owned(), "/user/desk".try_into().unwrap(), ToOne),
                DataLoader::new("desk".to_owned(), "/user/other".try_into().unwrap(), ToOne),
            ],
            vec![LoadedData::new([], []), LoadedData::new([], [])],
            USER.clone(),
            1,
        );

        assert_eq!(Value::Null, actual);
    }

    #[test]
    pub fn unknown_destination_is_skipped() {
        let actual = load_user(
            vec![DataLoader::new(
                "desk".to_owned(),
                "/unknown/desk".try_into().unwrap(),
                ToOne,
            )],
            vec![LoadedData::new([], [])],
            USER.clone(),
            1,
        );

        assert_eq!(USER.clone(), actual);
    }

    #[test]
    pub fn json_pointer_without_destination_is_skipped() {
        let actual = load_user(
            vec![DataLoader::new(
                "desk".to_owned(),
                "/".try_into().unwrap(),
                ToOne,
            )],
            vec![LoadedData::new([], [])],
            USER.clone(),
            1,
        );

        assert_eq!(USER.clone(), actual);
    }
}

pub mod nesting {
    use crate::data_loader::Multiplicity::{ToMany, ToOne};
    use crate::data_loader::*;
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;
    use serde_json::{json, Value};
    use test_log::test;

    lazy_static! {
        static ref USER: Value = json!({
            "id": 1,
            "name": "John",
            "some array": [1],
        });
        static ref CAT: Value = json!({
            "type":"cat",
        });
        static ref DOG: Value = json!({
            "type":"dog",
        });
    }
    #[test]
    pub fn one_object_is_nested() {
        let actual = load_user(
            vec![DataLoader::new(
                "pet".to_owned(),
                "/user/pet".try_into().unwrap(),
                ToOne,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pet": CAT.clone(),
            }),
            actual
        );
    }

    #[test]
    pub fn one_array_is_nested() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": [CAT.clone()]
            }),
            actual
        );
    }

    #[test]
    pub fn two_assignments_can_be_made() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new(
                [(2, CAT.clone()), (3, DOG.clone())],
                [(1, vec![2, 3])],
            )],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
              "some array": [1],
                "pets": [CAT.clone(), DOG.clone()]
            }),
            actual
        );
    }

    #[test]
    pub fn two_assignments_with_different_order_are_preserved() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new(
                [(2, CAT.clone()), (3, DOG.clone())],
                [(1, vec![3, 2])],
            )],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": [DOG.clone(), CAT.clone()]
            }),
            actual
        );
    }

    #[test]
    pub fn empty_middle_object_is_nested() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets/cats".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": {
                    "cats": [CAT.clone()]
                }
            }),
            actual
        );
    }

    #[test]
    pub fn empty_array_is_nested() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets/0".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": [
                    [CAT.clone()]
                ]
            }),
            actual
        );
    }

    #[test]
    pub fn mixed_empty_json_is_nested() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets/0/cats".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": [{
                    "cats": [CAT.clone()]
                }]
            }),
            actual
        );
    }

    #[test]
    pub fn missing_array_indices_are_filled_with_nulls() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets/3/cats".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": [
                    null,
                    null,
                    null,
                    {
                        "cats": [CAT.clone()]
                }]
            }),
            actual
        );
    }

    #[test]
    pub fn one_past_last_index_works() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/pets/-/cats".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1],
                "pets": [
                    {
                        "cats": [CAT.clone()]
                }]
            }),
            actual
        );
    }

    #[test]
    pub fn already_present_number_ignores_data() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/id".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(USER.clone(), actual);
    }

    #[test]
    pub fn already_present_bool_value_ignores_data() {
        let root = json!({
            "name": true,
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/name".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(root.clone(), actual);
    }

    #[test]
    pub fn already_present_string_value_ignores_data() {
        let root = json!({
            "name": "hello",
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/name".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(root.clone(), actual);
    }

    #[test]
    pub fn nesting_behind_primitive_value_ignores_data() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/id/unused".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(USER.clone(), actual);
    }

    #[test]
    pub fn nesting_in_present_object_ignores_data() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(USER.clone(), actual);
    }

    #[test]
    pub fn nesting_in_present_array_ignores_data() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/some array".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(USER.clone(), actual);
    }

    #[test]
    pub fn nesting_in_nested_array_ignores_data() {
        let root = json!({
            "some array": [[1]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/some array".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(root.clone(), actual);
    }

    #[test]
    pub fn nesting_in_deeply_nested_array_ignores_data() {
        let root = json!({
            "array": [[[[1]]]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/array/0".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(root.clone(), actual);
    }

    #[test]
    pub fn nesting_in_deeply_nested_array_works() {
        let root = json!({
            "array": [[[[true]]]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/array/0/1".try_into().unwrap(),
                ToOne,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(
            json!({
                "array": [[[[true]], CAT.clone()]],
            }),
            actual
        );
    }

    #[test]
    pub fn appending_in_deeply_nested_array_works() {
        let root = json!({
            "array": [[[[true]]]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/array/-/0".try_into().unwrap(),
                ToOne,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(
            json!({
                "array": [[[[true]]], [CAT.clone()]],
            }),
            actual
        );
    }

    #[test]
    pub fn appending_and_nesting_in_deeply_nested_array_works() {
        let root = json!({
            "array": [[[[true]]]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/array/0/1/0".try_into().unwrap(),
                ToOne,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(
            json!({
                "array": [[[[true]], [CAT.clone()]]],
            }),
            actual
        );
    }

    #[test]
    pub fn appending_in_deeply_nested_array_ignores_data() {
        let root = json!({
            "array": [[[[1]]]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/array/-".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(
            json!({
                "array": [[[[1]]], [CAT.clone()]],
            }),
            actual
        );
    }

    #[test]
    pub fn nesting_in_object_in_deeply_nested_array_ignores_data() {
        let root = json!({
            "array": [[[[1]]]],
        });
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/array/key".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            root.clone(),
            1,
        );

        assert_eq!(root.clone(), actual);
    }

    #[test]
    pub fn setting_value_in_array_exteds_with_nulls() {
        let actual = load_user(
            vec![DataLoader::new(
                "pets".to_owned(),
                "/user/some array/3".try_into().unwrap(),
                ToMany,
            )],
            vec![LoadedData::new([(2, CAT.clone())], [(1, vec![2])])],
            USER.clone(),
            1,
        );

        assert_eq!(
            json!({
                "id": 1,
                "name": "John",
                "some array": [1, null, null, [ CAT.clone() ]],
            }),
            actual
        );
    }
}
