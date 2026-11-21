// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Client-side accounting against the server's per-IP byte budgets.
//!
//! `/info` publishes `hourly_bytes_per_ip` and `daily_bytes_per_ip` but not how much of them is still free: the
//! server keeps that per client IP and does not reveal it. The best a client can do is (1) refuse a run that is
//! larger than the whole budget, and (2) subtract what *this client* already moved in the same window. Bytes that
//! other programs behind the same public IP used are invisible; the server's 429 (handled separately, fail fast)
//! is the final word.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use super::error::{BudgetWindow, SpeedError};
use super::server::ServerLimits;

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

/// Bytes this client moved per server in the last 24 hours. Cheap to clone via `Arc`; in memory only.
#[derive(Debug, Default)]
pub struct UsageLedger {
    entries: Mutex<HashMap<String, VecDeque<(Instant, u64)>>>,
}

impl UsageLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, VecDeque<(Instant, u64)>>> {
        // A poisoned lock only means another thread panicked while holding plain counters.
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record `bytes` moved to or from `server` (its `host:port`) at `now`.
    pub fn record(&self, server: &str, bytes: u64, now: Instant) {
        if bytes == 0 {
            return;
        }
        let mut map = self.lock();
        let queue = map.entry(server.to_owned()).or_default();
        queue.push_back((now, bytes));
        while queue
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > DAY)
        {
            queue.pop_front();
        }
    }

    /// Bytes recorded for `server` within the last `window`.
    pub fn used(&self, server: &str, window: Duration, now: Instant) -> u64 {
        self.lock().get(server).map_or(0, |queue| {
            queue
                .iter()
                .filter(|(at, _)| now.saturating_duration_since(*at) <= window)
                .fold(0u64, |sum, (_, bytes)| sum.saturating_add(*bytes))
        })
    }

    /// Refuse a run of `requested` bytes that cannot fit the published budgets (`0` = unlimited). Checks the
    /// hourly budget first, then the daily one.
    pub fn check(
        &self,
        server: &str,
        requested: u64,
        limits: &ServerLimits,
        now: Instant,
    ) -> Result<(), SpeedError> {
        for (window, span, limit) in [
            (BudgetWindow::Hour, HOUR, limits.hourly_bytes_per_ip),
            (BudgetWindow::Day, DAY, limits.daily_bytes_per_ip),
        ] {
            if limit == 0 {
                continue;
            }
            let available = limit.saturating_sub(self.used(server, span, now));
            if requested > available {
                return Err(SpeedError::BudgetExceeded {
                    window,
                    requested_bytes: requested,
                    limit_bytes: limit,
                    available_bytes: available,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(hourly: u64, daily: u64) -> ServerLimits {
        ServerLimits {
            hourly_bytes_per_ip: hourly,
            daily_bytes_per_ip: daily,
            ..ServerLimits::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_larger_than_the_whole_budget_is_refused() {
        let ledger = UsageLedger::new();
        let error = ledger
            .check("a:1", 60 << 30, &limits(50 << 30, 0), Instant::now())
            .unwrap_err();
        assert_eq!(
            error,
            SpeedError::BudgetExceeded {
                window: BudgetWindow::Hour,
                requested_bytes: 60 << 30,
                limit_bytes: 50 << 30,
                available_bytes: 50 << 30,
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn earlier_usage_in_the_window_shrinks_the_budget_and_expires() {
        let ledger = UsageLedger::new();
        let l = limits(10_000, 25_000);
        ledger.record("a:1", 7_000, Instant::now());
        assert!(ledger.check("a:1", 3_000, &l, Instant::now()).is_ok());
        let error = ledger.check("a:1", 3_001, &l, Instant::now()).unwrap_err();
        assert!(matches!(
            error,
            SpeedError::BudgetExceeded {
                window: BudgetWindow::Hour,
                available_bytes: 3_000,
                ..
            }
        ));
        // Another server has its own account.
        assert!(ledger.check("b:1", 10_000, &l, Instant::now()).is_ok());
        // An hour and a second later the hourly window is empty again, the daily one is not.
        tokio::time::advance(HOUR + Duration::from_secs(1)).await;
        assert!(ledger.check("a:1", 10_000, &l, Instant::now()).is_ok());
        assert_eq!(ledger.used("a:1", DAY, Instant::now()), 7_000);
        ledger.record("a:1", 17_000, Instant::now());
        let l = limits(100_000, 25_000);
        let error = ledger.check("a:1", 5_000, &l, Instant::now()).unwrap_err();
        assert!(matches!(
            error,
            SpeedError::BudgetExceeded {
                window: BudgetWindow::Day,
                available_bytes: 1_000,
                ..
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_means_unlimited() {
        let ledger = UsageLedger::new();
        ledger.record("a:1", u64::MAX / 2, Instant::now());
        assert!(ledger
            .check("a:1", u64::MAX / 2, &limits(0, 0), Instant::now())
            .is_ok());
    }
}
