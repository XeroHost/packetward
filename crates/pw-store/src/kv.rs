// SPDX-License-Identifier: GPL-3.0-or-later
//! Small typed key/value store (JSON text) for settings and state: the allowlist, config, the
//! Guardian policy, the original RDP firewall snapshot.

use rusqlite::{params, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Result, StoreError};
use crate::store::Store;

/// Longest key accepted (bytes).
pub const MAX_KEY_BYTES: usize = 256;
/// Largest JSON value accepted (bytes).
pub const MAX_VALUE_BYTES: usize = 8 * 1024 * 1024;

fn check_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "kv key must be 1..={MAX_KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let text = serde_json::to_string(value)?;
    if text.len() > MAX_VALUE_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "kv value is {} bytes (limit {MAX_VALUE_BYTES})",
            text.len()
        )));
    }
    Ok(text)
}

impl Store {
    /// The value under `key`, decoded as `T`. A stored value that does not decode as `T` is an
    /// error (`StoreError::Json`), not a miss: settings must not silently reset.
    pub fn kv_get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        match self.kv_get_json(key)? {
            Some(text) => Ok(Some(serde_json::from_str(&text)?)),
            None => Ok(None),
        }
    }

    /// The raw JSON text under `key`.
    pub fn kv_get_json(&self, key: &str) -> Result<Option<String>> {
        check_key(key)?;
        self.with(|conn| {
            Ok(conn
                .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
                .optional()?)
        })
    }

    /// Sets (replacing) `key`; one atomic statement. `now_ms` is recorded as the update time.
    pub fn kv_set<T: Serialize + ?Sized>(&self, key: &str, value: &T, now_ms: i64) -> Result<()> {
        check_key(key)?;
        let text = encode(value)?;
        self.with(|conn| {
            conn.execute(
                "INSERT INTO kv(key, value, updated_ms) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_ms = excluded.updated_ms",
                params![key, text, now_ms],
            )?;
            Ok(())
        })
    }

    /// Sets `key` only if it does not exist yet. Returns true when this call wrote it, false when a
    /// value was already there (which is left untouched). Use it for state that must never be
    /// overwritten by accident, such as the original RDP firewall snapshot. Atomic across threads
    /// and processes (single `INSERT ... ON CONFLICT DO NOTHING`).
    pub fn kv_set_if_absent<T: Serialize + ?Sized>(
        &self,
        key: &str,
        value: &T,
        now_ms: i64,
    ) -> Result<bool> {
        check_key(key)?;
        let text = encode(value)?;
        self.with(|conn| {
            Ok(conn.execute(
                "INSERT INTO kv(key, value, updated_ms) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(key) DO NOTHING",
                params![key, text, now_ms],
            )? == 1)
        })
    }

    /// Deletes `key`; true if it existed.
    pub fn kv_delete(&self, key: &str) -> Result<bool> {
        check_key(key)?;
        self.with(|conn| Ok(conn.execute("DELETE FROM kv WHERE key = ?1", [key])? > 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Policy {
        mode: String,
        ttl: u32,
        ranges: Vec<String>,
    }

    #[test]
    fn typed_roundtrip_and_replace() {
        let s = mem();
        assert_eq!(s.kv_get::<Policy>("guardian.policy").unwrap(), None);
        let p = Policy {
            mode: "monitor".into(),
            ttl: 600,
            ranges: vec!["10.0.0.0/8".into()],
        };
        s.kv_set("guardian.policy", &p, 1).unwrap();
        assert_eq!(s.kv_get::<Policy>("guardian.policy").unwrap(), Some(p));
        s.kv_set("guardian.policy", &"other", 2).unwrap();
        assert_eq!(
            s.kv_get::<String>("guardian.policy").unwrap().as_deref(),
            Some("other")
        );
        // Wrong type is an error, not a silent miss.
        assert!(matches!(
            s.kv_get::<Policy>("guardian.policy"),
            Err(StoreError::Json(_))
        ));
        assert_eq!(
            s.kv_get_json("guardian.policy").unwrap().as_deref(),
            Some("\"other\"")
        );
    }

    #[test]
    fn set_is_idempotent() {
        let s = mem();
        s.kv_set("k", &1, 1).unwrap();
        s.kv_set("k", &1, 1).unwrap();
        assert_eq!(s.kv_get::<i32>("k").unwrap(), Some(1));
    }

    #[test]
    fn delete() {
        let s = mem();
        s.kv_set("k", &1, 1).unwrap();
        assert!(s.kv_delete("k").unwrap());
        assert!(!s.kv_delete("k").unwrap());
        assert_eq!(s.kv_get::<i32>("k").unwrap(), None);
    }

    #[test]
    fn set_if_absent_never_overwrites() {
        let s = mem();
        assert!(s.kv_set_if_absent("rdp.snapshot", &"original", 1).unwrap());
        assert!(!s.kv_set_if_absent("rdp.snapshot", &"second", 2).unwrap());
        assert_eq!(
            s.kv_get::<String>("rdp.snapshot").unwrap().as_deref(),
            Some("original")
        );
        // After an explicit delete it can be written again.
        s.kv_delete("rdp.snapshot").unwrap();
        assert!(s.kv_set_if_absent("rdp.snapshot", &"third", 3).unwrap());
    }

    #[test]
    fn set_if_absent_has_exactly_one_winner_across_threads() {
        let s = Arc::new(mem());
        let wins = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let (s, wins) = (Arc::clone(&s), Arc::clone(&wins));
                thread::spawn(move || {
                    if s.kv_set_if_absent("once", &i, 0).unwrap() {
                        wins.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(wins.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn set_if_absent_has_one_winner_across_handles_on_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        let a = Store::open(&path).unwrap().store;
        let b = Store::open(&path).unwrap().store;
        assert!(a.kv_set_if_absent("snap", &1, 0).unwrap());
        assert!(!b.kv_set_if_absent("snap", &2, 0).unwrap());
        assert_eq!(b.kv_get::<i32>("snap").unwrap(), Some(1));
    }

    #[test]
    fn hostile_keys_and_values() {
        let s = mem();
        let key = "k'; DROP TABLE kv; --";
        let value = "v\0with\0nul and 'quotes' \" \\";
        s.kv_set(key, &value, 1).unwrap();
        assert_eq!(s.kv_get::<String>(key).unwrap().as_deref(), Some(value));
        let big = "é".repeat(1_000_000);
        s.kv_set("big", &big, 1).unwrap();
        assert_eq!(s.kv_get::<String>("big").unwrap(), Some(big));
        assert!(s.kv_set("", &1, 1).is_err());
        assert!(s.kv_set(&"k".repeat(MAX_KEY_BYTES + 1), &1, 1).is_err());
        assert!(s.kv_get::<i32>("").is_err());
        let too_big = "x".repeat(MAX_VALUE_BYTES);
        assert!(s.kv_set("huge", &too_big, 1).is_err());
        assert!(s.kv_set_if_absent("huge", &too_big, 1).is_err());
        assert_eq!(s.kv_get::<String>("huge").unwrap(), None);
    }
}
