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

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::notify_systemd;
#[cfg(not(target_os = "linux"))]
mod other;
#[cfg(not(target_os = "linux"))]
use other::notify_systemd;

use std::str::FromStr;
use std::time::Duration;

use tracing::debug;
use tracing::warn;

use tokio::task::spawn_blocking;
use tokio::time;

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
        warn!("watchdog failed to notify about termination: {}", e);
    }
}

/// See man 5 systemd.service
/// and man 3 sd_notify
pub async fn watchdog() {
    let watchdog_interval = compute_watchdog_interval();
    let mut clock = time::interval(Duration::from_micros(watchdog_interval));
    debug!("watchdog will run every {} us", watchdog_interval);

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

fn compute_watchdog_interval() -> u64 {
    let default = 10_000_000;
    let raw = std::env::var("WATCHDOG_USEC");
    let microseconds: u64 = raw
        .ok()
        .as_deref()
        .map(u64::from_str)
        .and_then(Result::ok)
        .unwrap_or(default);
    microseconds * 4 / 5
}
