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

use chrono::Duration;
use chrono::Local;
use clap::Arg;
use clap::ArgAction::Count;
use clap::ArgMatches;
use clap::Command;
use log::debug;
use log::error;
use log::LevelFilter;
use log4rs::config::Appender;
use log4rs::config::Config;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;
use tiny_auth_business::token::Token;
use tiny_auth_main::config::parser::parse_config;
use tiny_auth_main::http::state;
use tiny_auth_main::http::Constructor;
pub const FLAG_VERBOSE: &str = "verbose";
pub const FLAG_CONFIG: &str = "config";
pub const FLAG_USER: &str = "user";
pub const FLAG_CLIENT: &str = "client";
pub const FLAG_SCOPE: &str = "scope";

fn main() {
    let args = parse_arguments();
    initialise_logging(args.get_count(FLAG_VERBOSE));

    debug!("Starting up");

    let config_path = args
        .get_one::<String>(FLAG_CONFIG)
        .map(String::as_str)
        .unwrap_or(tiny_auth_main::cli_parser::FLAG_CONFIG_DEFAULT);
    debug!("Config is at {}", config_path);

    debug!("Parsing config");
    let config = parse_config(config_path);

    let di = match state::Constructor::new(&config) {
        Err(e) => {
            error!("Failed to read config: {}", e);
            return;
        }
        Ok(v) => v,
    };

    let store = di.user_store();

    let user = match store.get(
        args.get_one::<String>(FLAG_USER)
            .map(String::as_str)
            .unwrap(),
    ) {
        None => {
            error!("user not found");
            return;
        }
        Some(v) => v,
    };

    let store = match di.get_client_store() {
        None => {
            error!("Failed to read clients");
            return;
        }
        Some(v) => v,
    };

    let client = match store.get(
        args.get_one::<String>(FLAG_CLIENT)
            .map(String::as_str)
            .unwrap(),
    ) {
        None => {
            error!("client not found");
            return;
        }
        Some(v) => v,
    };

    let store = match di.get_scope_store() {
        None => {
            error!("Failed to read scopes");
            return;
        }
        Some(v) => v,
    };

    let scope = match store.get(
        args.get_one::<String>(FLAG_SCOPE)
            .map(String::as_str)
            .unwrap(),
    ) {
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

    let issuer = di.get_issuer_config();
    token.set_issuer(&issuer.issuer_url);

    match serde_json::to_string_pretty(&token) {
        Err(_) => error!("Failed to serialize data"),
        Ok(v) => println!("{}", v),
    };
}

pub fn parse_arguments() -> ArgMatches {
    let app = Command::new("Scope debugger for tiny-auth")
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("VERGEN_GIT_SHA"),
            " ",
            env!("VERGEN_BUILD_TIMESTAMP"),
        ))
        .about("Compute what claims are added to a token")
        .arg(
            Arg::new(FLAG_VERBOSE)
                .short('v')
                .long(FLAG_VERBOSE)
                .help("Output information while running")
                .action(Count),
        )
        .arg(
            Arg::new(FLAG_USER)
                .short('u')
                .long(FLAG_USER)
                .help("Name of the user")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::new(FLAG_CLIENT)
                .short('c')
                .long(FLAG_CLIENT)
                .help("Name of the client")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::new(FLAG_SCOPE)
                .short('s')
                .long(FLAG_SCOPE)
                .help("Name of the scope")
                .value_name("STRING")
                .required(true),
        )
        .arg(
            Arg::new(FLAG_CONFIG)
                .short('C')
                .long(FLAG_CONFIG)
                .help("The config file to run with")
                .value_name("STRING")
                .default_value(tiny_auth_main::cli_parser::FLAG_CONFIG_DEFAULT),
        );
    app.get_matches()
}

pub fn initialise_logging(verbosity_level: u8) {
    let stdout = log4rs::append::console::ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{level} {m}{n}")))
        .build();

    let level = match verbosity_level {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let config = Config::builder().appender(Appender::builder().build("stdout", Box::new(stdout)));

    if let Err(e) = config
        .build(Root::builder().appender("stdout").build(level))
        .map(log4rs::init_config)
    {
        eprintln!("could not configure logging: {}", e);
        std::process::exit(1);
    }
}
