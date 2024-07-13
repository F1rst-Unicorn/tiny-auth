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

use clap::Arg;
use clap::ArgAction::Count;
use clap::ArgMatches;
use clap::Command;
use serde::Serialize;
use tiny_auth_business::password::Password;
use tiny_auth_main::config::parser::parse_config;
use tiny_auth_main::logging::initialise_from_verbosity;
use tracing::debug;
use tracing::error;

pub const FLAG_VERBOSE: &str = "verbose";
pub const FLAG_USERNAME: &str = "username";
pub const FLAG_PASSWORD: &str = "password";
pub const FLAG_CONFIG: &str = "config";

fn main() {
    let args = parse_arguments();
    initialise_from_verbosity(args.get_count(FLAG_VERBOSE));

    debug!("Starting up");

    let config_path = args
        .get_one::<String>(FLAG_CONFIG)
        .map(String::as_str)
        .unwrap_or(tiny_auth_main::cli_parser::FLAG_CONFIG_DEFAULT);
    debug!("Config is at {}", config_path);

    debug!("Parsing config");
    let config = parse_config(config_path);

    let password = PasswordWrapper {
        password: Password::new(
            args.get_one::<String>(FLAG_USERNAME)
                .map(String::as_str)
                .unwrap(),
            args.get_one::<String>(FLAG_PASSWORD)
                .map(String::as_str)
                .unwrap(),
            &config.crypto.pepper,
        ),
    };

    match serde_yaml::to_string(&password) {
        Err(e) => {
            error!("Could not dump password: {}", e);
        }
        Ok(password) => {
            println!("{}", password);
        }
    }
}

#[derive(Serialize)]
struct PasswordWrapper {
    #[serde(with = "serde_yaml::with::singleton_map")]
    password: Password,
}

pub fn parse_arguments() -> ArgMatches {
    let app = Command::new("Password encoder for tiny-auth")
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("VERGEN_GIT_SHA"),
            " ",
            env!("VERGEN_BUILD_TIMESTAMP"),
        ))
        .about("Encrypt passwords for users and clients of tiny-auth")
        .arg(
            Arg::new(FLAG_VERBOSE)
                .short('v')
                .long(FLAG_VERBOSE)
                .help("Output information while running")
                .action(Count),
        )
        .arg(
            Arg::new(FLAG_USERNAME)
                .short('u')
                .long(FLAG_USERNAME)
                .help("Name of the user or client")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::new(FLAG_PASSWORD)
                .short('p')
                .long(FLAG_PASSWORD)
                .help("Password to encrypt")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::new(FLAG_CONFIG)
                .short('c')
                .long(FLAG_CONFIG)
                .help("The config file to run with")
                .value_name("STRING")
                .default_value("/etc/tiny-auth/config.yml"),
        );
    app.get_matches()
}
