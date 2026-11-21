// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Result cache for AbuseIPDB lookups. The trait is storage-agnostic: `pw-store` implements it over its
//! `intel_cache` table later; [`MemoryAbuseCache`] is the in-process implementation (and the test fake).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::AbuseReport;
use crate::UnixSecs;

/// A stored result with the time it was fetched. The TTL is applied by the client, not by the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedAbuse {
    pub report: AbuseReport,
    pub fetched_at: UnixSecs,
}

/// Synchronous key-value store of results by canonical IP address. Implementations must be cheap (a map or a
/// single indexed SQLite row); they are called from async code without `spawn_blocking`.
pub trait AbuseCache: Send + Sync {
    fn get(&self, ip: IpAddr) -> Option<CachedAbuse>;
    fn put(&self, ip: IpAddr, entry: CachedAbuse);
    fn remove(&self, ip: IpAddr);
}

/// Bounded in-memory cache; when full, the oldest entry is evicted.
#[derive(Debug)]
pub struct MemoryAbuseCache {
    capacity: usize,
    entries: Mutex<HashMap<IpAddr, CachedAbuse>>,
}

impl MemoryAbuseCache {
    pub const DEFAULT_CAPACITY: usize = 10_000;

    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, CachedAbuse>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for MemoryAbuseCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AbuseCache for MemoryAbuseCache {
    fn get(&self, ip: IpAddr) -> Option<CachedAbuse> {
        self.lock().get(&ip).cloned()
    }

    fn put(&self, ip: IpAddr, entry: CachedAbuse) {
        let mut entries = self.lock();
        if !entries.contains_key(&ip) && entries.len() >= self.capacity {
            let oldest = entries
                .iter()
                .min_by_key(|(_, cached)| cached.fetched_at)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                entries.remove(&oldest);
            }
        }
        entries.insert(ip, entry);
    }

    fn remove(&self, ip: IpAddr) {
        self.lock().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(at: u64) -> CachedAbuse {
        CachedAbuse {
            report: AbuseReport::default(),
            fetched_at: at,
        }
    }

    #[test]
    fn stores_replaces_and_removes() {
        let cache = MemoryAbuseCache::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(cache.get(ip).is_none());
        cache.put(ip, entry(1));
        cache.put(ip, entry(2));
        assert_eq!(cache.get(ip).unwrap().fetched_at, 2);
        assert_eq!(cache.len(), 1);
        cache.remove(ip);
        assert!(cache.is_empty());
    }

    #[test]
    fn the_oldest_entry_is_evicted_when_full() {
        let cache = MemoryAbuseCache::with_capacity(2);
        let (a, b, c): (IpAddr, IpAddr, IpAddr) = (
            "1.1.1.1".parse().unwrap(),
            "2.2.2.2".parse().unwrap(),
            "3.3.3.3".parse().unwrap(),
        );
        cache.put(a, entry(10));
        cache.put(b, entry(20));
        cache.put(c, entry(30));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(a).is_none());
        assert!(cache.get(b).is_some() && cache.get(c).is_some());
        // Updating an existing key never evicts.
        cache.put(b, entry(40));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(c).is_some());
    }
}
