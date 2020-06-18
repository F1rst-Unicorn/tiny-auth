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

use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::path::Path;

use log::error;

pub fn read_file(file_path: impl AsRef<Path>) -> Result<String, Error> {
    let mut file = File::open(file_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

pub fn iterate_directory<T: AsRef<Path> + Debug>(path: T) -> Option<fs::ReadDir> {
    match fs::metadata(&path) {
        Err(e) => {
            error!("Could not read store {:?}: {}", path, e);
            return None;
        }
        Ok(metadata) => {
            if !metadata.is_dir() {
                error!("{:?} is no directory", path);
                return None;
            }
        }
    }
    match fs::read_dir(path) {
        Err(e) => {
            error!("Could not list files in directory: {}", e);
            None
        }
        Ok(files) => Some(files),
    }
}

pub fn generate_random_string(length: u32) -> String {
    let mut result = String::new();
    for _ in 0..length {
        let mut char = 'ö';
        while !char.is_ascii_alphanumeric() {
            char = rand::random::<u8>().into();
        }
        result.push(char);
    }
    result
}
