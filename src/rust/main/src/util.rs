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

use std::fmt::{Debug, Display};
use std::fs;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::path::Path;

use tracing::error;

pub fn read_file(file_path: impl AsRef<Path>) -> Result<String, Error> {
    let mut file = File::open(file_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

pub fn iterate_directory<T: AsRef<Path> + Debug + Display>(path: T) -> Option<fs::ReadDir> {
    match fs::metadata(&path) {
        Err(e) => {
            error!(%path, %e, "could not read store");
            return None;
        }
        Ok(metadata) => {
            if !metadata.is_dir() {
                error!(%path, "not a directory");
                return None;
            }
        }
    }
    match fs::read_dir(path) {
        Err(e) => {
            error!(%e, "could not list files in directory");
            None
        }
        Ok(files) => Some(files),
    }
}
