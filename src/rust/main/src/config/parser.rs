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
use thiserror::Error;
use tracing::trace;
use tracing::{error, instrument, warn};

const EXIT_CODE: i32 = 2;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("failed to parse yaml: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

#[instrument(skip_all, fields(path))]
pub fn parse_config(path: &str) -> Config {
    match parse_config_fallibly(path) {
        Err(e) => {
            error!(%e);
            exit(EXIT_CODE);
        }
        Ok(v) => v,
    }
}

#[instrument(skip_all, fields(path))]
pub fn parse_config_fallibly(path: &str) -> Result<Config, ParseError> {
    let raw_config = read_config(path)?
        .into_iter()
        .next()
        .ok_or(ParseError::Other("no config found".into()))?;
    trace!(%raw_config, "complete configuration");
    parse_raw_config(&raw_config)
}

fn read_config(path: &str) -> Result<Vec<String>, ParseError> {
    let metadata = fs::metadata(path)?;
    if metadata.file_type().is_dir() {
        Ok(traverse_directory(path)?)
    } else if metadata.file_type().is_file() {
        Ok(vec![read(path)?])
    } else {
        warn!("ignoring file");
        Ok(Vec::new())
    }
}

fn traverse_directory(path: &str) -> Result<Vec<String>, ParseError> {
    let content = fs::read_dir(path)?;

    let mut result = Vec::new();

    for entry in content {
        let entry = entry?;
        let entry_path = entry.path();
        let entry_path_string = entry_path.to_str().unwrap();
        let content = read_config(entry_path_string)?;

        result.extend(content);
    }
    Ok(result)
}

fn parse_raw_config(raw_config: &str) -> Result<Config, ParseError> {
    let deserializer = serde_yaml::Deserializer::from_str(raw_config);
    Ok(serde_yaml::with::singleton_map_recursive::deserialize(
        deserializer,
    )?)
}
