// SPDX-License-Identifier: GPL-3.0-or-later
//! Reverse-DNS names for MTR hops: a bounded, expiring cache in front of any [`ReverseLookup`].

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::Instant;

/// Most entries kept; the oldest is evicted first.
pub const CACHE_CAPACITY: usize = 1024;
/// How long an answer (positive *or* negative) is trusted.
pub const CACHE_TTL: Duration = Duration::from_secs(300);
/// Longest a single reverse lookup may take, whatever the caller asks for.
pub const MAX_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Shortest lookup timeout.
pub const MIN_LOOKUP_TIMEOUT: Duration = Duration::from_millis(100);

/// Something that can turn an address into a host name (usually a PTR query).
pub trait ReverseLookup: Send + Sync + 'static {
    /// The name of `ip`, or `None` when there is none or the lookup failed.
    fn reverse(&self, ip: IpAddr) -> impl Future<Output = Option<String>> + Send;
}

/// A [`ReverseLookup`] that never finds anything (names disabled).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoReverse;

impl ReverseLookup for NoReverse {
    async fn reverse(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

#[derive(Debug)]
struct Entry {
    name: Option<String>,
    expires: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<IpAddr, Entry>,
    order: VecDeque<IpAddr>,
}

/// Reverse-lookup cache shared by consecutive MTR runs. Lookups run concurrently, each bounded by
/// a timeout, and failures are cached too so a dead resolver costs one timeout, not one per cycle.
#[derive(Debug)]
pub struct NameCache<R> {
    lookup: Arc<R>,
    timeout: Duration,
    inner: Mutex<Inner>,
}

impl NameCache<NoReverse> {
    /// A cache that never resolves anything.
    pub fn disabled() -> Self {
        Self::new(Arc::new(NoReverse), MIN_LOOKUP_TIMEOUT)
    }
}

impl<R: ReverseLookup> NameCache<R> {
    /// Cache in front of `lookup`; each lookup is abandoned after `timeout` (clamped to
    /// 100 ms..=5 s).
    pub fn new(lookup: Arc<R>, timeout: Duration) -> Self {
        Self {
            lookup,
            timeout: timeout.clamp(MIN_LOOKUP_TIMEOUT, MAX_LOOKUP_TIMEOUT),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cached name for `ip`, if a lookup found one and it has not expired.
    pub fn name(&self, ip: IpAddr) -> Option<String> {
        let inner = self.guard();
        inner
            .map
            .get(&ip)
            .filter(|e| e.expires > Instant::now())
            .and_then(|e| e.name.clone())
    }

    fn needs_lookup(&self, ip: IpAddr) -> bool {
        let inner = self.guard();
        inner
            .map
            .get(&ip)
            .is_none_or(|e| e.expires <= Instant::now())
    }

    fn store(&self, ip: IpAddr, name: Option<String>) {
        let mut inner = self.guard();
        if inner.map.remove(&ip).is_some() {
            inner.order.retain(|k| *k != ip);
        }
        while inner.map.len() >= CACHE_CAPACITY {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.map.remove(&oldest);
        }
        inner.order.push_back(ip);
        inner.map.insert(
            ip,
            Entry {
                name,
                expires: Instant::now() + CACHE_TTL,
            },
        );
    }

    /// Number of cached entries (positive and negative).
    pub fn len(&self) -> usize {
        self.guard().map.len()
    }

    /// True when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up every address in `ips` that is not cached (or expired), concurrently. Returns when
    /// all lookups finished or timed out, so it takes at most about one timeout in total.
    pub async fn resolve(&self, ips: &[IpAddr]) {
        let mut seen = Vec::new();
        let mut set = JoinSet::new();
        for &ip in ips {
            if seen.contains(&ip) || !self.needs_lookup(ip) {
                continue;
            }
            seen.push(ip);
            let lookup = Arc::clone(&self.lookup);
            let timeout = self.timeout;
            set.spawn(async move {
                let name = tokio::time::timeout(timeout, lookup.reverse(ip))
                    .await
                    .unwrap_or(None);
                (ip, name)
            });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((ip, name)) => self.store(ip, name),
                Err(e) => tracing::warn!("reverse lookup task failed: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixed {
        calls: AtomicUsize,
        delay: Duration,
    }

    impl ReverseLookup for Fixed {
        async fn reverse(&self, ip: IpAddr) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            match ip {
                IpAddr::V4(v4) if v4.octets()[3] == 1 => Some("gw.example.net".to_owned()),
                _ => None,
            }
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cache(delay: Duration, timeout: Duration) -> (Arc<Fixed>, NameCache<Fixed>) {
        let f = Arc::new(Fixed {
            calls: AtomicUsize::new(0),
            delay,
        });
        (Arc::clone(&f), NameCache::new(f, timeout))
    }

    #[tokio::test(start_paused = true)]
    async fn resolves_and_caches_including_negatives() {
        let (f, c) = cache(Duration::from_millis(5), Duration::from_secs(1));
        let ips = [ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.1")];
        c.resolve(&ips).await;
        assert_eq!(c.name(ip("10.0.0.1")).as_deref(), Some("gw.example.net"));
        assert_eq!(c.name(ip("10.0.0.2")), None);
        assert_eq!(
            f.calls.load(Ordering::SeqCst),
            2,
            "duplicates looked up once"
        );
        c.resolve(&ips).await;
        assert_eq!(
            f.calls.load(Ordering::SeqCst),
            2,
            "second round is all cache hits"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lookups_run_in_parallel_and_are_bounded_by_timeout() {
        let (f, c) = cache(Duration::from_secs(60), Duration::from_millis(500));
        let ips: Vec<IpAddr> = (1..=5).map(|i| ip(&format!("10.0.0.{i}"))).collect();
        let t0 = Instant::now();
        c.resolve(&ips).await;
        assert_eq!(t0.elapsed(), Duration::from_millis(500));
        assert_eq!(f.calls.load(Ordering::SeqCst), 5);
        assert_eq!(c.name(ip("10.0.0.1")), None, "a timeout is not a name");
        // ... and the failure is remembered, so it is not retried.
        c.resolve(&ips).await;
        assert_eq!(f.calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn entries_expire() {
        let (f, c) = cache(Duration::ZERO, Duration::from_secs(1));
        c.resolve(&[ip("10.0.0.1")]).await;
        tokio::time::advance(CACHE_TTL + Duration::from_secs(1)).await;
        assert_eq!(c.name(ip("10.0.0.1")), None);
        c.resolve(&[ip("10.0.0.1")]).await;
        assert_eq!(f.calls.load(Ordering::SeqCst), 2);
        assert_eq!(c.name(ip("10.0.0.1")).as_deref(), Some("gw.example.net"));
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_is_bounded() {
        let (_f, c) = cache(Duration::ZERO, Duration::from_secs(1));
        for i in 0..(CACHE_CAPACITY + 50) {
            c.store(ip(&format!("10.1.{}.{}", i / 250, i % 250)), None);
        }
        assert_eq!(c.len(), CACHE_CAPACITY);
        assert!(!c.is_empty());
    }

    #[tokio::test]
    async fn disabled_cache_finds_nothing() {
        let c = NameCache::disabled();
        c.resolve(&[ip("10.0.0.1")]).await;
        assert_eq!(c.name(ip("10.0.0.1")), None);
    }
}
