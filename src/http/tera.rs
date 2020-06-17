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

use std::collections::HashMap;

use tera::Result;
use tera::Tera;
use tera::Value;

use log::error;

pub fn load_template_engine(static_files_root: &str) -> Result<Tera> {
    let template_path = static_files_root.to_string() + "/templates/";

    let mut tera = match Tera::new(&(template_path + "**/*")) {
        Ok(t) => t,
        Err(e) => {
            error!("Parsing error(s): {}", e);
            return Err(e);
        }
    };

    tera.register_function("url", url_mapper);
    tera.register_function("translate", translator);
    tera.register_function("static", static_mapper);
    Ok(tera)
}

fn url_mapper(args: &HashMap<String, Value>) -> Result<Value> {
    match args.get("name") {
        Some(val) => Ok(val.clone()),
        None => {
            error!("no url name given");
            Err("oops".into())
        }
    }
}

fn translator(args: &HashMap<String, Value>) -> Result<Value> {
    match args.get("term") {
        Some(val) => Ok(val.clone()),
        None => {
            error!("no term given");
            Err("oops".into())
        }
    }
}

fn static_mapper(args: &HashMap<String, Value>) -> Result<Value> {
    match args.get("name") {
        Some(val) => Ok(val.clone()),
        None => {
            error!("no name given");
            Err("oops".into())
        }
    }
}
