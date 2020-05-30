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

mod cli_parser;
mod config;
mod domain;
mod http;
mod logging;
mod protocol;
mod store;
mod systemd;
mod util;

use config::parser::parse_config;

use log::error;
use log::info;

fn main() {
    let arguments = cli_parser::parse_arguments();
    logging::initialise(
        arguments
            .value_of(cli_parser::FLAG_LOG_CONFIG)
            .expect("Missing default value in cli_parser"),
    );

    info!("Starting up");

    let config_path = arguments
        .value_of(cli_parser::FLAG_CONFIG)
        .expect("Missing default value in cli_parser");
    info!("Config is at {}", config_path);

    info!("Parsing config");
    let config = parse_config(config_path);

    if let Err(e) = http::run(config.web, config.crypto) {
        error!("Server failed: {:#?}", e);
    }
}
