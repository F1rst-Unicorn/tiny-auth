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
use crate::data_loader::Multiplicity::ToOne;
use crate::json_pointer::{ArrayAccess, JsonPointer, PastLastArrayElement};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use tracing::{debug, error, instrument, Level};
use tracing::{span, warn};

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Multiplicity {
    ToOne,
    ToMany,
}

#[derive(Clone)]
pub struct DataLoader {
    pub name: String,
    pub location: JsonPointer,
    pub multiplicity: Multiplicity,
}

impl DataLoader {
    pub fn new(name: String, location: JsonPointer, multiplicity: Multiplicity) -> Self {
        Self {
            name,
            location,
            multiplicity,
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct LoadedData {
    pub data: BTreeMap<i32, Value>,
    assignments: BTreeMap<i32, Vec<i32>>,
}

impl LoadedData {
    pub fn new(
        data: impl IntoIterator<Item = (i32, Value)>,
        assignments: impl IntoIterator<Item = (i32, Vec<i32>)>,
    ) -> Self {
        Self {
            data: data.into_iter().collect(),
            assignments: assignments.into_iter().collect(),
        }
    }
}

pub fn load_client(
    data_loaders: Vec<DataLoader>,
    loaded_data: Vec<LoadedData>,
    client: Value,
    id: i32,
) -> Value {
    load_with_root_data(data_loaders, loaded_data, client, id, "client")
}

pub fn load_user(
    data_loaders: Vec<DataLoader>,
    loaded_data: Vec<LoadedData>,
    user: Value,
    id: i32,
) -> Value {
    load_with_root_data(data_loaders, loaded_data, user, id, "user")
}

fn load_with_root_data(
    mut data_loaders: Vec<DataLoader>,
    mut loaded_data: Vec<LoadedData>,
    root: Value,
    id: i32,
    kind: &str,
) -> Value {
    data_loaders.push(DataLoader::new(
        kind.to_string(),
        ("/".to_string() + kind).try_into().unwrap(),
        ToOne,
    ));
    loaded_data.push(LoadedData::new([(id, root)], []));
    load(data_loaders, loaded_data)
}

pub fn load(data_loaders: Vec<DataLoader>, loaded_data: Vec<LoadedData>) -> Value {
    if data_loaders.len() != loaded_data.len() {
        error!(data_loaders = %data_loaders.len(),
            loaded_data = %loaded_data.len(),
            "length of data loaders and loaded_data don't match! Please report a bug");
        return Value::Null;
    }

    let mut loaded_data: BTreeMap<String, LoadedData> = loaded_data
        .into_iter()
        .enumerate()
        .map(|(index, data)| (data_loaders[index].name.clone(), data))
        .collect::<BTreeMap<_, _>>();

    if data_loaders.len() != loaded_data.len() {
        warn!(data_loaders = %data_loaders.len(),
            loaded_data = %loaded_data.len(),
            "data loaders have no unique names");
        return Value::Null;
    }

    for data_loader in data_loaders.iter().rev().skip(1) {
        let _data_loader_span = span!(Level::INFO, "", source = %data_loader.name).entered();
        let Some(destination) = data_loader.location.first() else {
            warn!("data loader location has no first element so it cannot be nested");
            continue;
        };
        let _destination_span = span!(Level::INFO, "", %destination).entered();
        let Some(mut source_objects) = loaded_data.remove(&data_loader.name) else {
            warn!("data loader will be ignored as no data was loaded");
            continue;
        };
        let Some(destination_objects) = loaded_data.get_mut(destination) else {
            warn!("data loader will be ignored as destination is not known");
            continue;
        };
        for (destination_id, destination_object) in destination_objects.data.iter_mut() {
            nest_data_into_destinations(
                data_loader,
                &mut source_objects,
                destination_id,
                destination_object,
            );
        }
    }

    data_loaders
        .last()
        .map(|v| &v.name)
        .and_then(|v| loaded_data.get_mut(v))
        .and_then(|v| v.data.pop_first())
        .map(|(_, v)| v)
        .unwrap()
}

#[instrument(skip_all, fields(%destination_id))]
fn nest_data_into_destinations(
    data_loader: &DataLoader,
    source_objects: &mut LoadedData,
    destination_id: &i32,
    destination_object: &mut Value,
) {
    let assignments = source_objects
        .assignments
        .remove(destination_id)
        .unwrap_or_default();

    let value_to_nest = if data_loader.multiplicity == ToOne {
        if assignments.len() > 1 {
            warn!(
                source_ids = assignments
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                "'to one' data loader assigns more than one object. Only the first is assigned"
            );
        }
        if let Some(source_id) = assignments.first() {
            if let Some(source_object) = source_objects.data.get(source_id).cloned() {
                source_object
            } else {
                warn!(%source_id, "assignment references unknown id");
                Value::Null
            }
        } else {
            debug!("destination has no source value");
            Value::Null
        }
    } else {
        let mut value_to_nest = Vec::default();
        for source_id in assignments {
            if let Some(source_object) = source_objects.data.get(&source_id).cloned() {
                value_to_nest.push(source_object);
            } else {
                warn!(%source_id, "assignment references unknown id");
            }
        }
        value_to_nest.into()
    };

    nest_into(
        destination_object,
        value_to_nest,
        data_loader.location.pop_first(),
    )
}

fn nest_into(destination: &mut Value, value_to_nest: Value, location: JsonPointer) {
    let current_step = location.first();
    *destination = match (destination.take(), current_step) {
        (value @ Value::Bool(_), _)
        | (value @ Value::Number(_), _)
        | (value @ Value::String(_), _) => {
            warn!("already occupied");
            value
        }
        (Value::Null, None) => value_to_nest,
        (Value::Null, Some(current_step)) => {
            if PastLastArrayElement::try_from(current_step).is_ok() {
                let mut array = vec![Value::Null];
                nest_into(
                    array.first_mut().unwrap(),
                    value_to_nest,
                    location.pop_first(),
                );
                array.into()
            } else if let Ok(ArrayAccess(index)) = ArrayAccess::try_from(current_step) {
                let mut array = vec![Value::Null; index + 1];
                nest_into(
                    array.last_mut().unwrap(),
                    value_to_nest,
                    location.pop_first(),
                );
                array.into()
            } else {
                let mut object = Map::new();
                object.insert(current_step.to_string(), Value::Null);
                nest_into(
                    object.get_mut(current_step).unwrap(),
                    value_to_nest,
                    location.pop_first(),
                );
                object.into()
            }
        }
        (value @ Value::Object(_), None) => {
            warn!("already occupied");
            value
        }
        (Value::Object(mut object), Some(current_step)) => {
            if let Some(attribute) = object.get_mut(current_step) {
                nest_into(attribute, value_to_nest, location.pop_first());
                object.into()
            } else {
                let mut value = Value::Null;
                nest_into(&mut value, value_to_nest, location.pop_first());
                object.insert(current_step.to_string(), value);
                object.into()
            }
        }
        (value @ Value::Array(_), None) => {
            warn!("already occupied");
            value
        }
        (Value::Array(mut array), Some(current_step)) => {
            if PastLastArrayElement::try_from(current_step).is_ok() {
                array.push(Value::Null);
                nest_into(
                    array.last_mut().unwrap(),
                    value_to_nest,
                    location.pop_first(),
                );
                array.into()
            } else if let Ok(ArrayAccess(index)) = ArrayAccess::try_from(current_step) {
                if let Some(element) = array.get_mut(index) {
                    nest_into(element, value_to_nest, location.pop_first());
                } else {
                    while array.len() < index + 1 {
                        array.push(Value::Null);
                    }
                    nest_into(
                        array.last_mut().unwrap(),
                        value_to_nest,
                        location.pop_first(),
                    );
                }
                array.into()
            } else {
                warn!(index = %current_step, "index is no valid array access");
                array.into()
            }
        }
    }
}
