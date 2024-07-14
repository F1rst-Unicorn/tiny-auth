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

use tiny_auth_main::cli_parser::FLAG_VERBOSE;
use tiny_auth_main::logging::initialise_from_verbosity;
use tracing::error;
use tracing::info;

fn main() {
    let arguments = cli_parser::parse_arguments();
    let verbosity_level = arguments.get_count(FLAG_VERBOSE);
    let handles = initialise_from_verbosity(verbosity_level);

    info!("starting up");

    let config_path = arguments
        .get_one(cli_parser::FLAG_CONFIG)
        .map(String::as_str)
        .unwrap_or(cli_parser::FLAG_CONFIG_DEFAULT);
    info!(%config_path);

    info!("parsing config");
    let config = parse_config(config_path);
    logging::reload_with_config(&config.log, &handles);

    if let Err(e) = runtime::run(config) {
        error!(%e);
    }
}
