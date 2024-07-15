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
use crate::config::{Fields, Format, Log, Time};
use std::env;
use std::str::FromStr;
use tracing::{debug, error, info, Subscriber};
use tracing_log::LogTracer;
use tracing_subscriber::fmt::format;
use tracing_subscriber::fmt::format::{FmtSpan, JsonFields};
use tracing_subscriber::fmt::time::{ChronoLocal, ChronoUtc, SystemTime, Uptime};
use tracing_subscriber::layer::{Layered, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::reload::Layer as ReloadLayer;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

pub fn initialise_from_verbosity(verbosity_level: u8) -> (FilterHandle, FormatHandle) {
    let filter = match verbosity_level {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
    .to_string();

    initialise_with_config(&Log {
        format: Format::Full,
        fields: Fields {
            ansi: env::var("NO_COLOR").map_or(true, |v| v.is_empty()),
            file: false,
            level: true,
            line_number: false,
            target: true,
            thread_id: false,
            thread_name: false,
            span_events: verbosity_level >= 2,
            time: if verbosity_level >= 1 {
                Time::SystemTime
            } else {
                Time::None
            },
        },
        filter: vec![filter],
    })
}

type FormatHandle = Handle<
    Box<dyn Layer<Layered<ReloadLayer<EnvFilter, Registry>, Registry>> + Send + Sync>,
    Layered<ReloadLayer<EnvFilter, Registry>, Registry>,
>;

type FilterHandle = Handle<EnvFilter, Registry>;

fn initialise_with_config(config: &Log) -> (FilterHandle, FormatHandle) {
    let filter_layer = match EnvFilter::from_str(&config.filter.join(",")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid log filters: {}", e);
            std::process::exit(1);
        }
    };
    let (filter_layer, reload_handle) = ReloadLayer::new(filter_layer);
    let (layer, format_handle) = ReloadLayer::new(build_format_layer(config));

    let subscriber = tracing_subscriber::registry().with(filter_layer);
    subscriber.with(layer).init();
    init_log();

    (reload_handle, format_handle)
}

fn build_format_layer<S>(config: &Log) -> Box<dyn Layer<S> + Send + Sync + 'static>
where
    for<'a> S: Subscriber + LookupSpan<'a>,
{
    let format = format()
        .with_target(config.fields.target)
        .with_ansi(config.fields.ansi)
        .with_file(config.fields.file)
        .with_level(config.fields.level)
        .with_line_number(config.fields.line_number)
        .with_thread_ids(config.fields.thread_id)
        .with_thread_names(config.fields.thread_name);

    match config.format {
        Format::Compact => {
            let format = format.compact();
            match &config.fields.time {
                Time::None => {
                    let format = format.without_time();
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Uptime => {
                    let format = format.with_timer(Uptime::default());
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::SystemTime => {
                    let format = format.with_timer(SystemTime::default());
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Utc {
                    format: time_format,
                } => {
                    let format = format.with_timer(ChronoUtc::new(time_format.clone()));
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Local {
                    format: time_format,
                } => {
                    let format = format.with_timer(ChronoLocal::new(time_format.clone()));
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
            }
        }
        Format::Pretty => {
            let format = format.pretty();
            match &config.fields.time {
                Time::None => {
                    let format = format.without_time();
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Uptime => {
                    let format = format.with_timer(Uptime::default());
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::SystemTime => {
                    let format = format.with_timer(SystemTime::default());
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Utc {
                    format: time_format,
                } => {
                    let format = format.with_timer(ChronoUtc::new(time_format.clone()));
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Local {
                    format: time_format,
                } => {
                    let format = format.with_timer(ChronoLocal::new(time_format.clone()));
                    fmt::layer()
                        .event_format(format)
                        .with_span_events(span_events(config))
                        .boxed()
                }
            }
        }
        Format::Full => match &config.fields.time {
            Time::None => {
                let format = format.without_time();
                fmt::layer()
                    .event_format(format)
                    .with_span_events(span_events(config))
                    .boxed()
            }
            Time::Uptime => {
                let format = format.with_timer(Uptime::default());
                fmt::layer()
                    .event_format(format)
                    .with_span_events(span_events(config))
                    .boxed()
            }
            Time::SystemTime => {
                let format = format.with_timer(SystemTime::default());
                fmt::layer()
                    .event_format(format)
                    .with_span_events(span_events(config))
                    .boxed()
            }
            Time::Utc {
                format: time_format,
            } => {
                let format = format.with_timer(ChronoUtc::new(time_format.clone()));
                fmt::layer()
                    .event_format(format)
                    .with_span_events(span_events(config))
                    .boxed()
            }
            Time::Local {
                format: time_format,
            } => {
                let format = format.with_timer(ChronoLocal::new(time_format.clone()));
                fmt::layer()
                    .event_format(format)
                    .with_span_events(span_events(config))
                    .boxed()
            }
        },
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
            match &config.fields.time {
                Time::None => {
                    let format = format.without_time();
                    fmt::layer()
                        .event_format(format)
                        .fmt_fields(JsonFields::new())
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Uptime => {
                    let format = format.with_timer(Uptime::default());
                    fmt::layer()
                        .event_format(format)
                        .fmt_fields(JsonFields::new())
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::SystemTime => {
                    let format = format.with_timer(SystemTime::default());
                    fmt::layer()
                        .event_format(format)
                        .fmt_fields(JsonFields::new())
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Utc {
                    format: time_format,
                } => {
                    let format = format.with_timer(ChronoUtc::new(time_format.clone()));
                    fmt::layer()
                        .event_format(format)
                        .fmt_fields(JsonFields::new())
                        .with_span_events(span_events(config))
                        .boxed()
                }
                Time::Local {
                    format: time_format,
                } => {
                    let format = format.with_timer(ChronoLocal::new(time_format.clone()));
                    fmt::layer()
                        .event_format(format)
                        .fmt_fields(JsonFields::new())
                        .with_span_events(span_events(config))
                        .boxed()
                }
            }
        }
    }
}

fn span_events(config: &Log) -> FmtSpan {
    if config.fields.span_events {
        FmtSpan::NEW | FmtSpan::CLOSE
    } else {
        FmtSpan::NONE
    }
}

pub fn reload_with_config(
    config: &Log,
    (filter_handle, format_handle): &(FilterHandle, FormatHandle),
) {
    debug!("swapping log filter");
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
    }

    debug!("swapping log format");
    let format_layer = build_format_layer(&config);
    if let Err(e) = format_handle.reload(format_layer) {
        error!(%e, "failed to update log format");
    }
    info!("log filter updated");
}

fn init_log() {
    if let Err(e) = LogTracer::init() {
        eprintln!("failed to initialise log crate bridge: {}", e);
        std::process::exit(1);
    }
}
