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
use tracing::error;
use tracing_log::LogTracer;

pub fn initialise_from_config_file(_file_path: &str) {
    tracing_subscriber::fmt::init();
    init_log();
}

pub fn initialise_from_verbosity(_verbosity_level: u8) {
    tracing_subscriber::fmt::init();
    init_log();
}

fn init_log() {
    if let Err(e) = LogTracer::init() {
        error!(%e, "failed to initialise log crate bridge");
        std::process::exit(1);
    }
}
