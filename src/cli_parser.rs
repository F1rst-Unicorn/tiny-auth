/*  tiny-auth: Tiny OIDC Provider
 *  Copyright (C) 2019 The cinit developers
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

use clap::App;
use clap::Arg;

pub const FLAG_VERBOSE: &str = "verbose";
pub const FLAG_CONFIG: &str = "config";
pub const FLAG_LOG_CONFIG: &str = "log";

pub fn parse_arguments<'a>() -> clap::ArgMatches<'a> {
    let app = App::new("tiny-auth")
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("VERGEN_SHA"),
            " ",
            env!("VERGEN_BUILD_TIMESTAMP"),
        ))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("config")
                .short("c")
                .long(FLAG_CONFIG)
                .value_name("PATH")
                .help("The config file or directory to run with")
                .takes_value(true)
                .default_value("/etc/tiny-auth/config.yml"),
        )
        .arg(
            Arg::with_name("log")
                .short("l")
                .long(FLAG_LOG_CONFIG)
                .value_name("PATH")
                .help("The log4rs logging configuration")
                .takes_value(true)
                .default_value("/etc/tiny-auth/log4rs.yml"),
        );
    app.get_matches()
}
