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

use crate::config::Config;
use crate::util::read_file as read;

use std::fs;
use std::process::exit;

use tracing::{error, instrument, trace, warn};

const EXIT_CODE: i32 = 1;

#[instrument]
pub fn parse_config(path: &str) -> Config {
    let raw_config = match read_config(path).into_iter().next() {
        None => {
            error!("not found");
            exit(EXIT_CODE);
        }
        Some(v) => v,
    };
    trace!(%raw_config, "complete configuration");
    parse_raw_config(&raw_config)
}

fn read_config(path: &str) -> Vec<String> {
    match fs::metadata(path) {
        Err(e) => {
            error!(%e, "failed to read metadata");
            exit(EXIT_CODE);
        }
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                traverse_directory(path)
            } else if metadata.file_type().is_file() {
                read_file(path)
            } else {
                warn!("ignoring file");
                Vec::new()
            }
        }
    }
}

fn read_file(path: &str) -> Vec<String> {
    match read(path) {
        Err(e) => {
            error!(%e, "failed to read file");
            exit(EXIT_CODE)
        }
        Ok(content) => vec![content],
    }
}

fn traverse_directory(path: &str) -> Vec<String> {
    let content = fs::read_dir(path);
    if let Err(e) = content {
        error!(%e, "failed to get directory content");
        exit(EXIT_CODE);
    }

    let mut result = Vec::new();

    for entry in content.unwrap() {
        if let Err(e) = entry {
            error!(%e, "failed to read file");
            exit(EXIT_CODE);
        }
        let entry_path = entry.unwrap().path();
        let entry_path_string = entry_path.to_str().unwrap();
        let content = read_config(entry_path_string);

        result.extend(content);
    }
    result
}

fn parse_raw_config(raw_config: &str) -> Config {
    let deserializer = serde_yaml::Deserializer::from_str(raw_config);
    match serde_yaml::with::singleton_map_recursive::deserialize(deserializer) {
        Err(e) => {
            log_config_error(e);
            exit(EXIT_CODE);
        }
        Ok(v) => v,
    }
}

fn log_config_error(e: serde_yaml::Error) {
    error!(%e, "could not parse config");
    trace!("error in configuration file");
}
