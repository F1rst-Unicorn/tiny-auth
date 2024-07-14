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

pub const FLAG_CONFIG: &str = "config";
pub const FLAG_CONFIG_DEFAULT: &str = "/etc/tiny-auth/config.yml";

pub const FLAG_VERBOSE: &str = "verbose";

pub fn parse_arguments() -> ArgMatches {
    let app = Command::new(env!("CARGO_PKG_NAME"))
        .version(concat!(
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("VERGEN_GIT_SHA"),
            " ",
            env!("VERGEN_BUILD_TIMESTAMP"),
        ))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::new("config")
                .short('c')
                .long(FLAG_CONFIG)
                .value_name("PATH")
                .help("The config file to run with")
                .num_args(1)
                .default_value(FLAG_CONFIG_DEFAULT),
        )
        .arg(
            Arg::new(FLAG_VERBOSE)
                .short('v')
                .long(FLAG_VERBOSE)
                .help("Verbosity before logging is initialised")
                .action(Count),
        );
    app.get_matches()
}
