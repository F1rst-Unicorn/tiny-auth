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

use systemd::daemon::notify;

use log::debug;
use log::error;
use log::trace;
use log::warn;

use tokio::task::spawn_blocking;
use tokio::time;

use std::time::Duration;

pub async fn notify_about_start() {
    let result = spawn_blocking(|| {
        notify_systemd(&[("READY", "1")]);
    })
    .await;

    if let Err(e) = result {
        warn!("watchdog failed to notify about startup: {}", e);
    }
}

pub async fn notify_about_termination() {
    let result = spawn_blocking(|| {
        notify_systemd(&[("STOPPING", "1")]);
    })
    .await;

    if let Err(e) = result {
        warn!("watchdog failed to notify about startup: {}", e);
    }
}

/// See man 5 systemd.service
/// and man 3 sd_notify
pub async fn watchdog() {
    let default_microseconds = 10_000_000;
    let microseconds =
        std::env::var("WATCHDOG_USEC").unwrap_or(format!("{}", default_microseconds));
    let microseconds: u64 = microseconds.parse().unwrap_or(default_microseconds);
    let watchdog_time = microseconds * 4 / 5;
    let mut clock = time::interval(Duration::from_micros(watchdog_time));
    debug!("watchdog will run every {} us", watchdog_time);
    loop {
        clock.tick().await;
        let result = spawn_blocking(|| {
            notify_systemd(&[("WATCHDOG", "1")]);
        })
        .await;

        if let Err(e) = result {
            warn!("watchdog failed to notify: {}", e);
        }
    }
}

fn notify_systemd(message: &[(&str, &str)]) {
    let result = notify(false, message.iter());
    match result {
        Ok(false) => trace!("Running outside systemd"),
        Err(e) => error!("error notifying systemd: {}", e),
        _ => (),
    }
}
