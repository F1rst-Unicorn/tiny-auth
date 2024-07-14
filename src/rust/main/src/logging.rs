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
use crate::config::{Fields, Format, Log};
use std::str::FromStr;
use tracing::{debug, error, info};
use tracing_log::LogTracer;
use tracing_subscriber::fmt::format;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload::{Handle, Layer};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};

pub fn initialise_from_verbosity(verbosity_level: u8) -> (Handle<EnvFilter, Registry>, ()) {
    let filter = match verbosity_level {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
    .to_string();

    initialise_with_config(&Log {
        format: Format::Full,
        fields: Fields {
            ansi: false,
            file: false,
            level: true,
            line_number: false,
            source_location: false,
            target: true,
            thread_id: false,
            thread_name: false,
        },
        filter: vec![filter],
    })
}

fn initialise_with_config(config: &Log) -> (Handle<EnvFilter, Registry>, ()) {
    let format = format()
        .with_target(config.fields.target)
        .with_ansi(config.fields.ansi)
        .with_file(config.fields.file)
        .with_level(config.fields.level)
        .with_line_number(config.fields.line_number)
        .with_thread_ids(config.fields.thread_id)
        .with_thread_names(config.fields.thread_name);

    let filter_layer = match EnvFilter::from_str(&config.filter.join(",")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid log filters: {}", e);
            std::process::exit(1);
        }
    };

    let (filter_layer, reload_handle) = Layer::new(filter_layer);

    let subscriber = tracing_subscriber::registry().with(filter_layer);
    match config.format {
        Format::Compact => {
            let format = format.compact();
            let layer = fmt::layer().event_format(format);
            subscriber.with(layer).init();
        }
        Format::Pretty => {
            let format = format.pretty();
            let layer = fmt::layer().event_format(format);
            subscriber.with(layer).init();
        }
        Format::Full => {
            let layer = fmt::layer().event_format(format);
            subscriber.with(layer).init();
        }
        Format::Json {
            flatten,
            current_span,
            span_list,
        } => {
            let format = format
                .json()
                .flatten_event(flatten)
                .with_current_span(current_span)
                .with_span_list(span_list);
            let layer = fmt::layer().event_format(format);
            subscriber.with(layer).init();
        }
    }
    init_log();

    (reload_handle, ())
}

pub fn reload_with_config(
    config: &Log,
    (filter_handle, format_handle): (Handle<EnvFilter, Registry>, ()),
) {
    debug!(?config.filter, "swapping log filter");
    let mut new_filter = match EnvFilter::from_str(&config.filter.join(",")) {
        Ok(v) => v,
        Err(e) => {
            error!(%e, "invalid log filters");
            return;
        }
    };
    if let Err(e) = filter_handle.modify(|filter| {
        std::mem::swap(&mut new_filter, filter);
    }) {
        error!(%e, "failed to update log filter");
    } else {
        info!("log filter updated");
    }
}

fn init_log() {
    if let Err(e) = LogTracer::init() {
        eprintln!("failed to initialise log crate bridge: {}", e);
        std::process::exit(1);
    }
}
