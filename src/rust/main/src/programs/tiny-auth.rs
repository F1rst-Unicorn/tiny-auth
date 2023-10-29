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

use tiny_auth_main::cli_parser;
use tiny_auth_main::config::parser::parse_config;
use tiny_auth_main::logging;
use tiny_auth_main::runtime;

use log::error;
use log::info;

fn main() {
    let arguments = cli_parser::parse_arguments();
    logging::initialise_from_config_file(
        arguments
            .get_one::<String>(cli_parser::FLAG_LOG_CONFIG)
            .map(String::as_str)
            .unwrap_or(cli_parser::FLAG_LOG_DEFAULT),
    );

    info!("Starting up");

    let config_path = arguments
        .get_one(cli_parser::FLAG_CONFIG)
        .map(String::as_str)
        .unwrap_or(cli_parser::FLAG_CONFIG_DEFAULT);
    info!("Config is at {}", config_path);

    info!("Parsing config");
    let config = parse_config(config_path);

    if let Err(e) = runtime::run(config) {
        error!("Server failed: {:#?}", e);
    }
}
