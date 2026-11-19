// SPDX-License-Identifier: GPL-3.0-or-later
//! Cache of intelligence lookups (reverse DNS, ASN, reputation...): `(namespace, key)` -> JSON
//! with an expiry.

use std::sync::atomic::Ordering;

use rusqlite::{params, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::store::Store;

const MAX_NAMESPACE_BYTES: usize = 64;
const MAX_KEY_BYTES: usize = 512;

fn check(ns: &str, key: &str) -> Result<()> {
    if ns.is_empty()
        || ns.len() > MAX_NAMESPACE_BYTES
        || key.is_empty()
        || key.len() > MAX_KEY_BYTES
    {
        return Err(StoreError::InvalidInput(format!(
            "cache namespace must be 1..={MAX_NAMESPACE_BYTES} bytes and key 1..={MAX_KEY_BYTES}"
        )));
    }
    Ok(())
}

fn evict(conn: &rusqlite::Connection, now_ms: i64, max_rows: u64) -> Result<usize> {
    let mut removed = conn.execute("DELETE FROM intel_cache WHERE expires_ms <= ?1", [now_ms])?;
    let max = i64::try_from(max_rows).unwrap_or(i64::MAX);
    // Over the cap: drop the entries that would expire soonest.
    removed += conn.execute(
        "DELETE FROM intel_cache WHERE (ns, key) IN ( \
           SELECT ns, key FROM intel_cache ORDER BY expires_ms DESC, ns, key LIMIT -1 OFFSET ?1)",
        [max],
    )?;
    Ok(removed)
}

impl Store {
    /// The cached value, or `None` when absent, expired (`expires_ms <= now_ms`, as for blocks) or
    /// undecodable as `T` (a cache miss, not an error: the shape may have changed between builds).
    pub fn cache_get<T: DeserializeOwned>(
        &self,
        ns: &str,
        key: &str,
        now_ms: i64,
    ) -> Result<Option<T>> {
        check(ns, key)?;
        let text: Option<String> = self.with(|conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM intel_cache WHERE ns = ?1 AND key = ?2 AND expires_ms > ?3",
                    params![ns, key, now_ms],
                    |r| r.get(0),
                )
                .optional()?)
        })?;
        Ok(text.and_then(|t| match serde_json::from_str(&t) {
            Ok(v) => Some(v),
            Err(error) => {
                tracing::debug!(%error, ns, "undecodable cache entry treated as a miss");
                None
            }
        }))
    }

    /// Stores (replacing) a value that is valid until `expires_ms`. Values over
    /// `Limits::cache_max_value_bytes` are refused. Every `Limits::prune_every` puts the cache is
    /// trimmed to `Limits::cache_max_rows` (soonest-to-expire first, after expired entries), so the
    /// bound is soft by at most that many rows between trims.
    pub fn cache_put<T: Serialize + ?Sized>(
        &self,
        ns: &str,
        key: &str,
        value: &T,
        expires_ms: i64,
        now_ms: i64,
    ) -> Result<()> {
        check(ns, key)?;
        let text = serde_json::to_string(value)?;
        if text.len() > self.limits.cache_max_value_bytes {
            return Err(StoreError::InvalidInput(format!(
                "cache value is {} bytes (limit {})",
                text.len(),
                self.limits.cache_max_value_bytes
            )));
        }
        let nth = self.cache_puts.fetch_add(1, Ordering::Relaxed) + 1;
        let trim = nth.is_multiple_of(self.limits.prune_every.max(1));
        self.with(|conn| {
            conn.execute(
                "INSERT INTO intel_cache(ns, key, value, expires_ms) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(ns, key) DO UPDATE SET value = excluded.value, expires_ms = excluded.expires_ms",
                params![ns, key, text, expires_ms],
            )?;
            if trim {
                evict(conn, now_ms, self.limits.cache_max_rows)?;
            }
            Ok(())
        })
    }

    /// Deletes expired entries and trims to the size bound; returns how many rows went.
    pub fn cache_prune(&self, now_ms: i64) -> Result<usize> {
        self.with(|conn| evict(conn, now_ms, self.limits.cache_max_rows))
    }

    /// Entries in the cache, expired or not.
    pub fn cache_count(&self) -> Result<u64> {
        self.with(|conn| {
            let n: i64 = conn.query_row("SELECT count(*) FROM intel_cache", [], |r| r.get(0))?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;
    use serde::Deserialize;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Rep {
        score: u8,
        isp: String,
    }

    #[test]
    fn put_get_roundtrip_and_namespaces() {
        let s = mem();
        let v = Rep {
            score: 90,
            isp: "ExampleNet".into(),
        };
        s.cache_put("abuseipdb", "1.2.3.4", &v, 1_000, 0).unwrap();
        s.cache_put("rdns", "1.2.3.4", &"host.example", 1_000, 0)
            .unwrap();
        assert_eq!(
            s.cache_get::<Rep>("abuseipdb", "1.2.3.4", 10).unwrap(),
            Some(v)
        );
        assert_eq!(
            s.cache_get::<String>("rdns", "1.2.3.4", 10)
                .unwrap()
                .as_deref(),
            Some("host.example")
        );
        assert_eq!(s.cache_get::<String>("rdns", "9.9.9.9", 10).unwrap(), None);
        assert_eq!(s.cache_get::<String>("asn", "1.2.3.4", 10).unwrap(), None);
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let s = mem();
        s.cache_put("n", "k", &1, 100, 0).unwrap();
        assert_eq!(s.cache_get::<i32>("n", "k", 99).unwrap(), Some(1));
        assert_eq!(s.cache_get::<i32>("n", "k", 100).unwrap(), None);
        assert_eq!(s.cache_get::<i32>("n", "k", 101).unwrap(), None);
    }

    #[test]
    fn put_twice_replaces() {
        let s = mem();
        s.cache_put("n", "k", &1, 100, 0).unwrap();
        s.cache_put("n", "k", &2, 200, 0).unwrap();
        s.cache_put("n", "k", &2, 200, 0).unwrap();
        assert_eq!(s.cache_count().unwrap(), 1);
        assert_eq!(s.cache_get::<i32>("n", "k", 150).unwrap(), Some(2));
    }

    #[test]
    fn undecodable_entry_is_a_miss() {
        let s = mem();
        s.cache_put("n", "k", &"text", 100, 0).unwrap();
        assert_eq!(s.cache_get::<Rep>("n", "k", 0).unwrap(), None);
    }

    #[test]
    fn prune_removes_expired_only() {
        let s = mem();
        s.cache_put("n", "a", &1, 100, 0).unwrap();
        s.cache_put("n", "b", &2, 200, 0).unwrap();
        s.cache_put("n", "c", &3, 300, 0).unwrap();
        assert_eq!(s.cache_prune(200).unwrap(), 2);
        assert_eq!(s.cache_count().unwrap(), 1);
        assert_eq!(s.cache_get::<i32>("n", "c", 200).unwrap(), Some(3));
        assert_eq!(s.cache_prune(200).unwrap(), 0);
    }

    #[test]
    fn size_is_bounded_dropping_soonest_to_expire() {
        let limits = Limits {
            cache_max_rows: 10,
            prune_every: 1,
            ..Limits::default()
        };
        let s = Store::open_in_memory_with(limits).unwrap();
        for i in 0..50 {
            s.cache_put("n", &format!("k{i}"), &i, 1_000 + i64::from(i), 0)
                .unwrap();
        }
        assert_eq!(s.cache_count().unwrap(), 10);
        // The ten latest-expiring entries survive.
        assert_eq!(s.cache_get::<i32>("n", "k49", 0).unwrap(), Some(49));
        assert_eq!(s.cache_get::<i32>("n", "k40", 0).unwrap(), Some(40));
        assert_eq!(s.cache_get::<i32>("n", "k39", 0).unwrap(), None);
    }

    #[test]
    fn put_prunes_expired_entries_when_trimming() {
        let limits = Limits {
            prune_every: 1,
            ..Limits::default()
        };
        let s = Store::open_in_memory_with(limits).unwrap();
        s.cache_put("n", "old", &1, 10, 0).unwrap();
        s.cache_put("n", "new", &2, 1_000, 500).unwrap();
        assert_eq!(s.cache_count().unwrap(), 1);
    }

    #[test]
    fn hostile_and_oversized_input() {
        let s = mem();
        let key = "k'; DROP TABLE intel_cache; --\0x";
        s.cache_put("ns'--", key, &"v\0'\"", 100, 0).unwrap();
        assert_eq!(
            s.cache_get::<String>("ns'--", key, 0).unwrap().as_deref(),
            Some("v\0'\"")
        );
        assert!(s.cache_put("", "k", &1, 1, 0).is_err());
        assert!(s.cache_put("n", "", &1, 1, 0).is_err());
        assert!(s
            .cache_put("n", &"k".repeat(MAX_KEY_BYTES + 1), &1, 1, 0)
            .is_err());
        let big = "x".repeat(s.limits().cache_max_value_bytes + 1);
        assert!(s.cache_put("n", "big", &big, 100, 0).is_err());
        assert_eq!(s.cache_count().unwrap(), 1);
    }
}
