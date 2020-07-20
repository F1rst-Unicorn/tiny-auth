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
use tiny_auth::domain::Token;
use tiny_auth::http::state;

use log4rs::config::Appender;
use log4rs::config::Config;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;

use log::debug;
use log::error;
use log::LevelFilter;

use chrono::Duration;
use chrono::Local;

use clap::App;
use clap::Arg;

pub const FLAG_VERBOSE: &str = "verbose";
pub const FLAG_CONFIG: &str = "config";
pub const FLAG_USER: &str = "user";
pub const FLAG_CLIENT: &str = "client";
pub const FLAG_SCOPE: &str = "scope";

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

    let di = state::Constructor::new(&config);

    let store = match di.build_user_store() {
        None => {
            error!("Failed to read users");
            return;
        }
        Some(v) => v,
    };

    let user = match store.get(args.value_of(FLAG_USER).unwrap()) {
        None => {
            error!("user not found");
            return;
        }
        Some(v) => v,
    };

    let store = match di.build_client_store() {
        None => {
            error!("Failed to read clients");
            return;
        }
        Some(v) => v,
    };

    let client = match store.get(args.value_of(FLAG_CLIENT).unwrap()) {
        None => {
            error!("client not found");
            return;
        }
        Some(v) => v,
    };

    let store = match di.build_scope_store() {
        None => {
            error!("Failed to read scopes");
            return;
        }
        Some(v) => v,
    };

    let scope = match store.get(args.value_of(FLAG_SCOPE).unwrap()) {
        None => {
            error!("scope not found");
            return;
        }
        Some(v) => v,
    };

    let mut token = Token::build(
        &user,
        &client,
        &[scope],
        Local::now(),
        Duration::minutes(1),
        0,
    );

    let issuer = match di.build_issuer_config() {
        None => {
            error!("Could not form token issuer");
            return;
        }
        Some(v) => v,
    };
    token.set_issuer(&issuer.issuer_url);

    match serde_json::to_string_pretty(&token) {
        Err(_) => error!("Failed to serialize data"),
        Ok(v) => println!("{}", v),
    };
}

pub fn parse_arguments<'a>() -> clap::ArgMatches<'a> {
    let app = App::new("Scope debugger for tiny-auth")
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("VERGEN_SHA"),
            " ",
            env!("VERGEN_BUILD_TIMESTAMP"),
        ))
        .about("Compute what claims are added to a token")
        .arg(
            Arg::with_name(FLAG_VERBOSE)
                .short("v")
                .long(FLAG_VERBOSE)
                .help("Output information while running")
                .multiple(true)
                .takes_value(false),
        )
        .arg(
            Arg::with_name(FLAG_USER)
                .short("u")
                .long(FLAG_USER)
                .help("Name of the user")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::with_name(FLAG_CLIENT)
                .short("c")
                .long(FLAG_CLIENT)
                .help("Name of the client")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::with_name(FLAG_SCOPE)
                .short("s")
                .long(FLAG_SCOPE)
                .help("Name of the scope")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::with_name(FLAG_CONFIG)
                .short("C")
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
