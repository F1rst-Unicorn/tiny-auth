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
use std::result::Result;

use log::{debug, error, trace, warn};

const EXIT_CODE: i32 = 1;

pub fn parse_config(path: &str) -> Config {
    let raw_config = read_config(path);
    debug!(
        "Complete configuration:\n{}",
        raw_config
            .iter()
            .flat_map(|s| s.chars())
            .collect::<String>()
    );
    parse_raw_config(&raw_config)
}

fn read_config(path: &str) -> Vec<String> {
    match fs::metadata(path) {
        Err(e) => {
            error!("Failed to read metadata of {}: {}", path, e);
            exit(EXIT_CODE);
        }
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                traverse_directory(path)
            } else if metadata.file_type().is_file() {
                read_file(path)
            } else {
                warn!("Ignoring file {}", path);
                Vec::new()
            }
        }
    }
}

fn read_file(path: &str) -> Vec<String> {
    match read(path) {
        Err(error) => {
            error!("Failed to read file {}: {}", path, error);
            exit(EXIT_CODE)
        }
        Ok(content) => vec![content],
    }
}

fn traverse_directory(path: &str) -> Vec<String> {
    let content = fs::read_dir(path);
    if let Err(err) = content {
        error!("Failed to get directory content of {}: {}", path, err);
        exit(EXIT_CODE);
    }

    let mut result = Vec::new();

    for entry in content.unwrap() {
        if let Err(err) = entry {
            error!("Failed to read {}: {}", path, err);
            exit(EXIT_CODE);
        }
        let entry_path = entry.unwrap().path();
        let entry_path_string = entry_path.to_str().unwrap();
        let content = read_config(entry_path_string);

        result.extend(content);
    }
    result
}

fn parse_raw_config(raw_config: &[String]) -> Config {
    let parse_result = raw_config.iter().map(|s| serde_yaml::from_str(s));

    let parse_errors: Vec<serde_yaml::Result<Config>> =
        parse_result.clone().filter(Result::is_err).collect();

    if !parse_errors.is_empty() {
        log_config_errors(parse_errors);
        exit(EXIT_CODE);
    } else {
        parse_result
            .map(Result::unwrap)
            .fold(Config::new(), Config::merge)
    }
}

fn log_config_errors(parse_errors: Vec<serde_yaml::Result<Config>>) {
    error!("Could not parse config: ");
    for error in parse_errors {
        error!("{:#?}", error.unwrap_err());
    }
    trace!("Error in configuration file");
}
