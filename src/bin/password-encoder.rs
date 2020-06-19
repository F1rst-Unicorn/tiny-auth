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

use tiny_auth::config::parser::parse_config;
use tiny_auth::domain::Password;

use log4rs::config::Appender;
use log4rs::config::Config;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;

use log::debug;
use log::error;
use log::LevelFilter;

use clap::App;
use clap::Arg;

pub const FLAG_VERBOSE: &str = "verbose";
pub const FLAG_USERNAME: &str = "username";
pub const FLAG_PASSWORD: &str = "password";
pub const FLAG_CONFIG: &str = "config";

fn main() {
    let args = parse_arguments();
    initialise_logging(args.occurrences_of(FLAG_VERBOSE));

    debug!("Starting up");

    let config_path = args
        .value_of(FLAG_CONFIG)
        .expect("Missing default value in cli_parser");
    debug!("Config is at {}", config_path);

    debug!("Parsing config");
    let config = parse_config(config_path);

    let password = Password::new(
        args.value_of(FLAG_USERNAME).unwrap(),
        args.value_of(FLAG_PASSWORD).unwrap(),
        &config.crypto.pepper,
    );

    match serde_yaml::to_string(&password) {
        Err(e) => {
            error!("Could not dump password: {}", e);
        }
        Ok(password) => {
            println!("{}", password);
        }
    }
}

pub fn parse_arguments<'a>() -> clap::ArgMatches<'a> {
    let app = App::new("Password encoder for tiny-auth")
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("VERGEN_SHA"),
            " ",
            env!("VERGEN_BUILD_TIMESTAMP"),
        ))
        .about("Encrypt passwords for users and clients of tiny-auth")
        .arg(
            Arg::with_name(FLAG_VERBOSE)
                .short("v")
                .long(FLAG_VERBOSE)
                .help("Output information while running")
                .multiple(true)
                .takes_value(false),
        )
        .arg(
            Arg::with_name(FLAG_USERNAME)
                .short("u")
                .long(FLAG_USERNAME)
                .help("Name of the user or client")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::with_name(FLAG_PASSWORD)
                .short("p")
                .long(FLAG_PASSWORD)
                .help("Password to encrypt")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::with_name(FLAG_CONFIG)
                .short("c")
                .long(FLAG_CONFIG)
                .help("The config file to run with")
                .value_name("STRING")
                .default_value("/etc/tiny-auth/config.yml"),
        );
    app.get_matches()
}

pub fn initialise_logging(verbosity_level: u64) {
    let stdout = log4rs::append::console::ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{level} {m}{n}")))
        .build();

    let level = match verbosity_level {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let config = Config::builder().appender(Appender::builder().build("stdout", Box::new(stdout)));

    let config = config
        .build(Root::builder().appender("stdout").build(level))
        .expect("Could not configure logging");

    log4rs::init_config(config).expect("Could not apply log config");
}
