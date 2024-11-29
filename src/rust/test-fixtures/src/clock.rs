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
use chrono::{DateTime, Local, TimeZone};
use tiny_auth_business::clock::Clock;

struct EpochClock;

impl Clock for EpochClock {
    fn now(&self) -> DateTime<Local> {
        Local.timestamp_opt(0, 0).unwrap()
    }
}

pub fn clock() -> impl Clock {
    EpochClock
}

struct SystemTimeClock;

impl Clock for SystemTimeClock {
    fn now(&self) -> DateTime<Local> {
        Local::now()
    }
}

pub fn system_time_clock() -> impl Clock {
    SystemTimeClock
}
