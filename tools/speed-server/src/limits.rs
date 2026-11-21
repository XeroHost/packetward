// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Per-client and global protection: request rate, concurrent tests, byte budgets, connection caps.
//!
//! All state lives behind one `Mutex`; every operation is O(1) and never awaits, so contention is
//! negligible next to the transfers themselves. Time is passed in explicitly so tests can drive it.
//!
//! Vocabulary: a *stream* is one download/upload request. A *test* is the group of streams from one
//! client that share a `?test=<id>`; a stream without an id is a test of its own. Concurrency limits are
//! applied to tests (and to streams inside one test), so PacketWard can open 4-8 parallel streams while a
//! lone client still cannot hold more than a couple of tests.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::config::{LimitsConfig, ServerConfig};
use crate::ip::limiter_key;

/// Upper bound on tracked client keys; protects memory against address-spraying.
const MAX_TRACKED_CLIENTS: usize = 100_000;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// Why a request was refused. Always maps to HTTP 429.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    /// Request rate exceeded.
    #[error("request rate limit exceeded")]
    RateLimited {
        /// Seconds until a token is available.
        retry_after_secs: u64,
    },
    /// Too many concurrent tests from this client.
    #[error("too many concurrent tests from this client")]
    TooManyTests,
    /// Too many streams inside one test.
    #[error("too many streams in this test")]
    TooManyStreams,
    /// The server is at its global concurrency limit.
    #[error("server is busy")]
    Busy,
    /// The hourly or daily byte budget is exhausted.
    #[error("byte budget exhausted")]
    BudgetExhausted {
        /// Seconds until the window resets.
        retry_after_secs: u64,
    },
}

impl Denied {
    /// Suggested `Retry-After` in seconds (>= 1).
    pub fn retry_after_secs(&self) -> u64 {
        match self {
            Denied::RateLimited { retry_after_secs }
            | Denied::BudgetExhausted { retry_after_secs } => (*retry_after_secs).max(1),
            Denied::TooManyTests | Denied::TooManyStreams | Denied::Busy => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    used: u64,
}

#[derive(Debug)]
struct ClientState {
    tests: HashMap<String, usize>,
    connections: usize,
    tokens: f64,
    last_refill: Instant,
    hour: Window,
    day: Window,
}

impl ClientState {
    fn new(now: Instant, capacity: f64) -> Self {
        Self {
            tests: HashMap::new(),
            connections: 0,
            tokens: capacity,
            last_refill: now,
            hour: Window {
                start: now,
                used: 0,
            },
            day: Window {
                start: now,
                used: 0,
            },
        }
    }

    fn roll_windows(&mut self, now: Instant) {
        if now.saturating_duration_since(self.hour.start) >= HOUR {
            self.hour = Window {
                start: now,
                used: 0,
            };
        }
        if now.saturating_duration_since(self.day.start) >= DAY {
            self.day = Window {
                start: now,
                used: 0,
            };
        }
    }

    fn idle(&self, now: Instant, refill_secs: f64) -> bool {
        self.tests.is_empty()
            && self.connections == 0
            && now
                .saturating_duration_since(self.last_refill)
                .as_secs_f64()
                >= refill_secs
            && now.saturating_duration_since(self.hour.start) >= HOUR
            && now.saturating_duration_since(self.day.start) >= DAY
    }
}

#[derive(Debug)]
struct State {
    clients: HashMap<IpAddr, ClientState>,
    global_tests: usize,
    next_anon: u64,
    last_sweep: Instant,
}

/// Counters exposed for tests and (future) metrics; none of them identify a client.
#[derive(Debug, Default)]
pub struct Stats {
    /// Bytes produced for downloads.
    pub generated_bytes: AtomicU64,
    /// Bytes received on uploads.
    pub received_bytes: AtomicU64,
    /// Streams currently running.
    pub active_streams: AtomicUsize,
    /// Requests refused with 429.
    pub rejected: AtomicU64,
}

/// The limiter. Cheap to share via `Arc`.
#[derive(Debug)]
pub struct Limiter {
    cfg: LimitsConfig,
    max_connections_per_ip: usize,
    state: Mutex<State>,
    stats: Arc<Stats>,
}

impl Limiter {
    /// Build a limiter from the validated configuration.
    pub fn new(
        limits: &LimitsConfig,
        server: &ServerConfig,
        stats: Arc<Stats>,
        now: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg: limits.clone(),
            max_connections_per_ip: server.max_connections_per_ip,
            state: Mutex::new(State {
                clients: HashMap::new(),
                global_tests: 0,
                next_anon: 0,
                last_sweep: now,
            }),
            stats,
        })
    }

    /// Shared counters.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock cannot leave the counters in a state worse than "slightly off";
        // keep serving instead of poisoning every future request.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn rate_capacity(&self) -> f64 {
        self.cfg.requests_per_minute_per_ip as f64
    }

    fn refill_secs(&self) -> f64 {
        // Time for a drained bucket to refill completely.
        60.0
    }

    fn sweep(&self, st: &mut State, now: Instant) {
        if now.saturating_duration_since(st.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        st.last_sweep = now;
        let refill = self.refill_secs();
        st.clients.retain(|_, c| !c.idle(now, refill));
    }

    fn client<'a>(
        &self,
        st: &'a mut State,
        key: IpAddr,
        now: Instant,
    ) -> Result<&'a mut ClientState, Denied> {
        self.sweep(st, now);
        if !st.clients.contains_key(&key) && st.clients.len() >= MAX_TRACKED_CLIENTS {
            // Force a sweep regardless of the interval before giving up.
            st.last_sweep = now - SWEEP_INTERVAL;
            self.sweep(st, now);
            if st.clients.len() >= MAX_TRACKED_CLIENTS {
                return Err(Denied::Busy);
            }
        }
        let cap = self.rate_capacity();
        Ok(st
            .clients
            .entry(key)
            .or_insert_with(|| ClientState::new(now, cap)))
    }

    fn deny(&self, d: Denied) -> Denied {
        self.stats.rejected.fetch_add(1, Ordering::Relaxed);
        d
    }

    /// Charge one request against the client's token bucket.
    pub fn check_request(&self, client: IpAddr, now: Instant) -> Result<(), Denied> {
        if self.cfg.requests_per_minute_per_ip == 0 {
            return Ok(());
        }
        let key = limiter_key(client);
        let cap = self.rate_capacity();
        let per_sec = cap / 60.0;
        let mut st = self.lock();
        let c = self.client(&mut st, key, now).map_err(|d| self.deny(d))?;
        let elapsed = now.saturating_duration_since(c.last_refill).as_secs_f64();
        c.tokens = (c.tokens + elapsed * per_sec).min(cap);
        c.last_refill = now;
        if c.tokens >= 1.0 {
            c.tokens -= 1.0;
            Ok(())
        } else {
            let wait = ((1.0 - c.tokens) / per_sec).ceil() as u64;
            Err(self.deny(Denied::RateLimited {
                retry_after_secs: wait,
            }))
        }
    }

    /// Register a connection from `peer`. `None` means "not counted" (limit disabled or trusted proxy).
    pub fn open_connection(
        self: &Arc<Self>,
        peer: IpAddr,
        now: Instant,
    ) -> Option<ConnectionGuard> {
        if self.max_connections_per_ip == 0 {
            return Some(ConnectionGuard {
                limiter: None,
                key: peer,
            });
        }
        let key = limiter_key(peer);
        let mut st = self.lock();
        let c = self.client(&mut st, key, now).ok()?;
        if c.connections >= self.max_connections_per_ip {
            return None;
        }
        c.connections += 1;
        Some(ConnectionGuard {
            limiter: Some(Arc::clone(self)),
            key,
        })
    }

    /// Start a transfer. `reserve` bytes are charged against the hourly/daily budgets immediately (a
    /// download knows its size); whatever the permit does not report as used is refunded when it drops.
    /// `test_id` groups parallel streams into one test.
    pub fn begin_transfer(
        self: &Arc<Self>,
        client: IpAddr,
        test_id: Option<&str>,
        reserve: u64,
        now: Instant,
    ) -> Result<TransferPermit, Denied> {
        let key = limiter_key(client);
        let mut st = self.lock();
        let global_tests = st.global_tests;
        let anon_id = st.next_anon;
        let c = self.client(&mut st, key, now).map_err(|d| self.deny(d))?;
        c.roll_windows(now);

        // Byte budgets first: they are the cheapest thing to explain to a client.
        self.check_budget(c, reserve, now)
            .map_err(|d| self.deny(d))?;

        let (test_key, new_test) = match test_id {
            Some(id) => match c.tests.get(id) {
                Some(&streams) => {
                    if streams >= self.cfg.max_streams_per_test {
                        return Err(self.deny(Denied::TooManyStreams));
                    }
                    (id.to_string(), false)
                }
                None => (id.to_string(), true),
            },
            None => (format!("\0anon{anon_id}"), true),
        };
        if new_test {
            let per_ip = self.cfg.max_concurrent_tests_per_ip;
            if per_ip != 0 && c.tests.len() >= per_ip {
                return Err(self.deny(Denied::TooManyTests));
            }
            let global = self.cfg.max_concurrent_tests_global;
            if global != 0 && global_tests >= global {
                return Err(self.deny(Denied::Busy));
            }
        }
        *c.tests.entry(test_key.clone()).or_insert(0) += 1;
        c.hour.used = c.hour.used.saturating_add(reserve);
        c.day.used = c.day.used.saturating_add(reserve);
        if new_test {
            st.global_tests += 1;
        }
        if test_id.is_none() {
            st.next_anon = st.next_anon.wrapping_add(1);
        }
        drop(st);
        self.stats.active_streams.fetch_add(1, Ordering::Relaxed);
        Ok(TransferPermit {
            limiter: Arc::clone(self),
            key,
            test_key,
            reserved: reserve,
            used: 0,
        })
    }

    fn check_budget(&self, c: &ClientState, extra: u64, now: Instant) -> Result<(), Denied> {
        for (limit, window, span) in [
            (self.cfg.hourly_bytes_per_ip, c.hour, HOUR),
            (self.cfg.daily_bytes_per_ip, c.day, DAY),
        ] {
            if limit == 0 {
                continue;
            }
            // A request larger than the whole budget can never succeed; the handler rejects that case
            // as a bad request before getting here, so treat it as exhausted rather than panicking.
            if window.used.saturating_add(extra) > limit || window.used >= limit {
                let remaining = span.saturating_sub(now.saturating_duration_since(window.start));
                return Err(Denied::BudgetExhausted {
                    retry_after_secs: remaining.as_secs() + 1,
                });
            }
        }
        Ok(())
    }

    fn release(&self, key: IpAddr, test_key: &str, refund: u64, now: Instant) {
        let mut st = self.lock();
        let mut test_gone = false;
        if let Some(c) = st.clients.get_mut(&key) {
            if let Some(n) = c.tests.get_mut(test_key) {
                *n -= 1;
                if *n == 0 {
                    c.tests.remove(test_key);
                    test_gone = true;
                }
            }
            // Only refund inside the window the reservation was made in; after a roll-over the bytes
            // were already forgotten, and used.saturating_sub never underflows.
            c.roll_windows(now);
            c.hour.used = c.hour.used.saturating_sub(refund);
            c.day.used = c.day.used.saturating_sub(refund);
        }
        if test_gone {
            st.global_tests = st.global_tests.saturating_sub(1);
        }
    }
}

/// Holds one stream slot (and its byte reservation). Dropping it frees the slot and refunds unused bytes.
#[derive(Debug)]
pub struct TransferPermit {
    limiter: Arc<Limiter>,
    key: IpAddr,
    test_key: String,
    reserved: u64,
    used: u64,
}

impl TransferPermit {
    /// Record `n` bytes actually transferred against the reservation. Cheap; no lock.
    pub fn add_used(&mut self, n: u64) {
        self.used = self.used.saturating_add(n);
    }

    /// Bytes transferred so far.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Charge `n` more bytes against the budgets (uploads, whose size is not known up front). Fails when
    /// the hourly or daily budget would be exceeded; nothing is charged in that case.
    pub fn charge(&mut self, n: u64) -> Result<(), Denied> {
        let now = Instant::now();
        let limiter = Arc::clone(&self.limiter);
        {
            let mut st = limiter.lock();
            if let Some(c) = st.clients.get_mut(&self.key) {
                c.roll_windows(now);
                // The check includes everything this permit already reserved or charged.
                if let Err(d) = limiter.check_budget(c, n, now) {
                    return Err(limiter.deny(d));
                }
                c.hour.used = c.hour.used.saturating_add(n);
                c.day.used = c.day.used.saturating_add(n);
            }
        }
        self.reserved = self.reserved.saturating_add(n);
        self.used = self.used.saturating_add(n);
        Ok(())
    }
}

impl Drop for TransferPermit {
    fn drop(&mut self) {
        let refund = self.reserved.saturating_sub(self.used);
        self.limiter
            .release(self.key, &self.test_key, refund, Instant::now());
        self.limiter
            .stats
            .active_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Holds one connection slot for a client.
#[derive(Debug)]
pub struct ConnectionGuard {
    limiter: Option<Arc<Limiter>>,
    key: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(l) = &self.limiter {
            let mut st = l.lock();
            if let Some(c) = st.clients.get_mut(&self.key) {
                c.connections = c.connections.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::v4;

    const GIB: u64 = 1 << 30;

    fn limiter(f: impl FnOnce(&mut LimitsConfig, &mut ServerConfig)) -> Arc<Limiter> {
        let mut l = LimitsConfig::default();
        let mut s = ServerConfig::default();
        f(&mut l, &mut s);
        Limiter::new(&l, &s, Arc::default(), Instant::now())
    }

    fn ip(n: u8) -> IpAddr {
        v4(198, 51, 100, n)
    }

    #[test]
    fn concurrent_tests_per_ip_are_limited_and_released() {
        let lim = limiter(|_, _| {});
        let now = Instant::now();
        let a = lim.begin_transfer(ip(1), None, 10, now).unwrap();
        let b = lim.begin_transfer(ip(1), None, 10, now).unwrap();
        let err = lim.begin_transfer(ip(1), None, 10, now).unwrap_err();
        assert_eq!(err, Denied::TooManyTests);
        // Another client is unaffected.
        let _c = lim.begin_transfer(ip(2), None, 10, now).unwrap();
        drop(a);
        let _d = lim.begin_transfer(ip(1), None, 10, now).unwrap();
        drop(b);
        assert_eq!(lim.stats().active_streams.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn streams_with_the_same_test_id_form_one_test_up_to_the_stream_cap() {
        let lim = limiter(|l, _| l.max_streams_per_test = 3);
        let now = Instant::now();
        let s1 = lim.begin_transfer(ip(1), Some("abc"), 0, now).unwrap();
        let _s2 = lim.begin_transfer(ip(1), Some("abc"), 0, now).unwrap();
        let _s3 = lim.begin_transfer(ip(1), Some("abc"), 0, now).unwrap();
        assert_eq!(
            lim.begin_transfer(ip(1), Some("abc"), 0, now).unwrap_err(),
            Denied::TooManyStreams
        );
        // A second test is fine, a third is not.
        let _t2 = lim.begin_transfer(ip(1), Some("def"), 0, now).unwrap();
        assert_eq!(
            lim.begin_transfer(ip(1), Some("ghi"), 0, now).unwrap_err(),
            Denied::TooManyTests
        );
        drop(s1);
        let _s4 = lim.begin_transfer(ip(1), Some("abc"), 0, now).unwrap();
    }

    #[test]
    fn global_test_limit() {
        let lim = limiter(|l, _| l.max_concurrent_tests_global = 2);
        let now = Instant::now();
        let _a = lim.begin_transfer(ip(1), None, 0, now).unwrap();
        let _b = lim.begin_transfer(ip(2), None, 0, now).unwrap();
        assert_eq!(
            lim.begin_transfer(ip(3), None, 0, now).unwrap_err(),
            Denied::Busy
        );
        // A stream joining an existing test does not need a new global slot.
        let lim = limiter(|l, _| l.max_concurrent_tests_global = 1);
        let _a = lim.begin_transfer(ip(1), Some("t"), 0, now).unwrap();
        let _b = lim.begin_transfer(ip(1), Some("t"), 0, now).unwrap();
    }

    #[test]
    fn zero_means_unlimited() {
        let lim = limiter(|l, _| {
            l.max_concurrent_tests_per_ip = 0;
            l.max_concurrent_tests_global = 0;
            l.requests_per_minute_per_ip = 0;
            l.hourly_bytes_per_ip = 0;
            l.daily_bytes_per_ip = 0;
        });
        let now = Instant::now();
        let permits: Vec<_> = (0..200)
            .map(|_| lim.begin_transfer(ip(1), None, 1 << 40, now).unwrap())
            .collect();
        assert_eq!(permits.len(), 200);
        for _ in 0..10_000 {
            lim.check_request(ip(1), now).unwrap();
        }
    }

    #[test]
    fn token_bucket_limits_then_refills() {
        let lim = limiter(|l, _| l.requests_per_minute_per_ip = 60);
        let t0 = Instant::now();
        for _ in 0..60 {
            lim.check_request(ip(1), t0).unwrap();
        }
        let err = lim.check_request(ip(1), t0).unwrap_err();
        assert_eq!(
            err,
            Denied::RateLimited {
                retry_after_secs: 1
            }
        );
        // One token per second.
        lim.check_request(ip(1), t0 + Duration::from_millis(1100))
            .unwrap();
        assert!(lim
            .check_request(ip(1), t0 + Duration::from_millis(1200))
            .is_err());
        // Other clients have their own bucket.
        lim.check_request(ip(2), t0).unwrap();
        // The bucket never exceeds its capacity.
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..60 {
            lim.check_request(ip(1), later).unwrap();
        }
        assert!(lim.check_request(ip(1), later).is_err());
    }

    #[test]
    fn ipv6_clients_share_a_64() {
        let lim = limiter(|l, _| l.requests_per_minute_per_ip = 2);
        let now = Instant::now();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        lim.check_request(a, now).unwrap();
        lim.check_request(b, now).unwrap();
        assert!(lim.check_request(a, now).is_err());
    }

    #[test]
    fn hourly_budget_blocks_then_resets() {
        let lim = limiter(|l, _| {
            l.max_download_bytes = GIB;
            l.hourly_bytes_per_ip = 4 * GIB;
            l.daily_bytes_per_ip = 100 * GIB;
        });
        let t0 = Instant::now();
        let mut a = lim.begin_transfer(ip(1), None, GIB, t0).unwrap();
        a.add_used(GIB);
        drop(a);
        for _ in 0..3 {
            let mut p = lim.begin_transfer(ip(1), None, GIB, t0).unwrap();
            p.add_used(GIB);
        }
        let err = lim
            .begin_transfer(ip(1), None, GIB, t0 + Duration::from_secs(10))
            .unwrap_err();
        match err {
            Denied::BudgetExhausted { retry_after_secs } => assert!(
                (3580..=3600).contains(&retry_after_secs),
                "{retry_after_secs}"
            ),
            other => panic!("unexpected {other:?}"),
        }
        // After the hour rolls over the client may transfer again.
        lim.begin_transfer(ip(1), None, GIB, t0 + HOUR + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn daily_budget_applies_independently() {
        let lim = limiter(|l, _| {
            l.max_download_bytes = GIB;
            l.hourly_bytes_per_ip = 0;
            l.daily_bytes_per_ip = 2 * GIB;
        });
        let t0 = Instant::now();
        for _ in 0..2 {
            let mut p = lim.begin_transfer(ip(1), None, GIB, t0).unwrap();
            p.add_used(GIB);
        }
        assert!(matches!(
            lim.begin_transfer(ip(1), None, GIB, t0 + HOUR * 5)
                .unwrap_err(),
            Denied::BudgetExhausted { .. }
        ));
        lim.begin_transfer(ip(1), None, GIB, t0 + DAY + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn unused_reservation_is_refunded() {
        let lim = limiter(|l, _| {
            l.max_download_bytes = GIB;
            l.hourly_bytes_per_ip = 2 * GIB;
            l.daily_bytes_per_ip = 0;
        });
        let t0 = Instant::now();
        // A client that aborts immediately must not burn its whole hour.
        for _ in 0..10 {
            let mut p = lim.begin_transfer(ip(1), None, GIB, t0).unwrap();
            p.add_used(1000);
        }
        // But what it really transferred was charged: 10 * 1000 bytes.
        let st = lim.lock();
        assert_eq!(st.clients.get(&ip(1)).unwrap().hour.used, 10_000);
    }

    #[test]
    fn upload_charge_respects_budget() {
        let lim = limiter(|l, _| {
            l.max_download_bytes = 1000;
            l.hourly_bytes_per_ip = 5000;
            l.daily_bytes_per_ip = 0;
        });
        let now = Instant::now();
        let mut p = lim.begin_transfer(ip(1), None, 0, now).unwrap();
        p.charge(3000).unwrap();
        p.charge(2000).unwrap();
        assert!(matches!(p.charge(1), Err(Denied::BudgetExhausted { .. })));
        assert_eq!(p.used(), 5000);
    }

    #[test]
    fn connection_cap_per_ip() {
        let lim = limiter(|_, s| s.max_connections_per_ip = 2);
        let now = Instant::now();
        let a = lim.open_connection(ip(1), now).unwrap();
        let _b = lim.open_connection(ip(1), now).unwrap();
        assert!(lim.open_connection(ip(1), now).is_none());
        assert!(lim.open_connection(ip(2), now).is_some());
        drop(a);
        assert!(lim.open_connection(ip(1), now).is_some());
    }

    #[test]
    fn idle_clients_are_swept_so_memory_stays_bounded() {
        let lim = limiter(|_, _| {});
        let t0 = Instant::now();
        for n in 0..=255u8 {
            lim.check_request(v4(10, 0, 0, n), t0).unwrap();
        }
        assert_eq!(lim.lock().clients.len(), 256);
        // Far in the future, any request triggers a sweep; windows have expired for everyone.
        lim.check_request(ip(1), t0 + DAY + Duration::from_secs(120))
            .unwrap();
        assert_eq!(lim.lock().clients.len(), 1);
    }

    #[test]
    fn active_transfers_survive_sweeps() {
        let lim = limiter(|_, _| {});
        let t0 = Instant::now();
        let _p = lim.begin_transfer(ip(1), None, 0, t0).unwrap();
        lim.check_request(ip(2), t0 + DAY * 2).unwrap();
        assert!(lim.lock().clients.contains_key(&ip(1)));
    }
}
