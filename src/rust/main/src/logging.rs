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

use log::LevelFilter;
use log4rs::config::Appender;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::Config;

pub fn initialise_from_config_file(file_path: &str) {
    if let Err(e) = log4rs::init_file(file_path, Default::default()) {
        eprintln!("Could not configure logging: {}", e);
        std::process::exit(1);
    }
}

pub fn initialise_from_verbosity(verbosity_level: u8) {
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
