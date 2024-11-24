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

use chrono::DateTime;
use chrono::Duration;
use chrono::Local;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::instrument;
use tracing::Level;

#[derive(Clone)]
pub struct RateLimiter {
    maximum_events: usize,

    duration: Duration,

    rates: Arc<RwLock<BTreeMap<String, BTreeSet<DateTime<Local>>>>>,
}

impl RateLimiter {
    pub fn new(maximum_events: usize, duration: Duration) -> Self {
        Self {
            maximum_events,
            duration,
            rates: Default::default(),
        }
    }

    #[instrument(level = Level::DEBUG, skip(self, rate_name))]
    pub async fn record_event(&self, rate_name: &str, event_time: DateTime<Local>) {
        let mut rates = self.rates.write().await;
        match rates.get_mut(rate_name) {
            None => {
                let mut events: BTreeSet<DateTime<Local>> = Default::default();
                events.insert(event_time);
                rates.insert(rate_name.to_owned(), events);
            }
            Some(events) => {
                events.insert(event_time);
            }
        }
    }

    #[instrument(level = Level::DEBUG, skip(self, rate_name))]
    pub async fn remove_event(&self, rate_name: &str, event_time: DateTime<Local>) {
        let mut rates = self.rates.write().await;
        if let Some(events) = rates.get_mut(rate_name) {
            events.remove(&event_time);
        }
    }

    pub async fn is_rate_above_maximum(&self, rate_name: &str, now: DateTime<Local>) -> bool {
        !self.is_rate_below_maximum(rate_name, now).await
    }

    pub async fn is_rate_below_maximum(&self, rate_name: &str, now: DateTime<Local>) -> bool {
        let mut rates = self.rates.write().await;
        match rates.get_mut(rate_name) {
            None => return true,
            Some(events) => {
                *events = events.split_off(&(now - self.duration));
            }
        }
        drop(rates);

        let rates = self.rates.read().await;
        match rates.get(rate_name) {
            None => true,
            Some(events) => events.len() <= self.maximum_events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use rstest::{fixture, rstest};
    use std::convert::TryInto;
    use test_log::test;

    #[rstest]
    #[test(tokio::test)]
    async fn empty_rate_is_ok(now: DateTime<Local>, rate_name: &str, uut: RateLimiter) {
        assert!(uut.is_rate_below_maximum(rate_name, now).await);
        assert!(!uut.is_rate_above_maximum(rate_name, now).await);
    }

    #[rstest]
    #[test(tokio::test)]
    async fn recording_max_events_is_still_ok(
        duration: Duration,
        events: usize,
        now: DateTime<Local>,
        rate_name: &str,
        uut: RateLimiter,
    ) {
        for i in 0..events {
            uut.record_event(
                rate_name,
                now - (duration / 2) + Duration::milliseconds(i.try_into().unwrap()),
            )
            .await;
        }

        assert_eq!(events, uut.rates.read().await.get(rate_name).unwrap().len());
        assert!(uut.is_rate_below_maximum(rate_name, now).await);
        assert!(!uut.is_rate_above_maximum(rate_name, now).await);
    }

    #[rstest]
    #[test(tokio::test)]
    async fn recording_one_more_than_max_events_is_not_ok(
        duration: Duration,
        events: usize,
        now: DateTime<Local>,
        rate_name: &str,
        uut: RateLimiter,
    ) {
        for i in 0..(events + 1) {
            uut.record_event(
                rate_name,
                now - (duration / 2) + Duration::milliseconds(i.try_into().unwrap()),
            )
            .await;
        }

        assert_eq!(
            events + 1,
            uut.rates.read().await.get(rate_name).unwrap().len()
        );
        assert!(!uut.is_rate_below_maximum(rate_name, now).await);
        assert!(uut.is_rate_above_maximum(rate_name, now).await);
    }

    #[rstest]
    #[test(tokio::test)]
    async fn removing_works(
        duration: Duration,
        events: usize,
        now: DateTime<Local>,
        rate_name: &str,
        uut: RateLimiter,
    ) {
        for i in 0..(events + 1) {
            uut.record_event(
                rate_name,
                now - (duration / 2) + Duration::milliseconds(i.try_into().unwrap()),
            )
            .await;
        }
        assert!(uut.is_rate_above_maximum(rate_name, now).await);
        assert!(!uut.is_rate_below_maximum(rate_name, now).await);

        uut.remove_event(rate_name, now - (duration / 2)).await;

        assert!(!uut.is_rate_above_maximum(rate_name, now).await);
        assert!(uut.is_rate_below_maximum(rate_name, now).await);
    }

    #[fixture]
    fn uut(events: usize, duration: Duration) -> RateLimiter {
        RateLimiter::new(events, duration)
    }

    #[fixture]
    fn duration() -> Duration {
        Duration::seconds(1)
    }

    #[fixture]
    fn events() -> usize {
        5
    }

    #[fixture]
    fn now() -> DateTime<Local> {
        Local.timestamp_opt(0, 0).unwrap()
    }

    #[fixture]
    fn rate_name() -> &'static str {
        "test"
    }
}