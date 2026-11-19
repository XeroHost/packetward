// SPDX-License-Identifier: GPL-3.0-or-later
//! Addresses with a successful RDP logon: the trust set the Guardian protects, kept beyond the
//! Security log's size and across restarts.

use std::net::IpAddr;

use rusqlite::{params, Row};
use serde::{Deserialize, Serialize};

use crate::error::{to_u64, Result, StoreError};
use crate::store::Store;

/// One trusted address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdpLogon {
    pub addr: IpAddr,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// Successful logons recorded from this address.
    pub count: u64,
}

fn row_to_logon(row: &Row<'_>) -> Result<RdpLogon> {
    let addr: String = row.get(0)?;
    Ok(RdpLogon {
        addr: addr
            .parse()
            .map_err(|_| StoreError::InvalidData(format!("stored rdp address {addr:?}")))?,
        first_seen_ms: row.get(1)?,
        last_seen_ms: row.get(2)?,
        count: to_u64(row.get(3)?, "rdp logon count")?,
    })
}

const UPSERT: &str = "INSERT INTO rdp_logons(addr, first_seen_ms, last_seen_ms, count) \
    VALUES (?1, ?2, ?2, 1) \
    ON CONFLICT(addr) DO UPDATE SET \
      first_seen_ms = min(first_seen_ms, excluded.first_seen_ms), \
      last_seen_ms = max(last_seen_ms, excluded.last_seen_ms), \
      count = min(count + 1, 9223372036854775807)";

impl Store {
    /// Records one successful logon from `addr` at `at_ms`: inserts, or bumps the count and keeps
    /// `last_seen` at the latest time seen (events may arrive out of order when the bounded initial
    /// log load runs after live ones). IPv4-mapped IPv6 addresses are stored as IPv4.
    pub fn rdp_logon_record(&self, addr: IpAddr, at_ms: i64) -> Result<()> {
        self.rdp_logons_record_many(&[(addr, at_ms)])
    }

    /// [`Store::rdp_logon_record`] for many events in one transaction (the initial log load).
    pub fn rdp_logons_record_many(&self, events: &[(IpAddr, i64)]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let max = i64::try_from(self.limits.rdp_logons_max).unwrap_or(i64::MAX);
        self.with(|conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            {
                let mut stmt = tx.prepare_cached(UPSERT)?;
                for (addr, at_ms) in events {
                    stmt.execute(params![addr.to_canonical().to_string(), at_ms])?;
                }
            }
            // Bound the table: the least recently seen addresses go first.
            tx.execute(
                "DELETE FROM rdp_logons WHERE addr IN ( \
                   SELECT addr FROM rdp_logons ORDER BY last_seen_ms DESC, addr LIMIT -1 OFFSET ?1)",
                [max],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Addresses last seen at or after `since_ms`, most recent first.
    pub fn rdp_logons_since(&self, since_ms: i64) -> Result<Vec<RdpLogon>> {
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT addr, first_seen_ms, last_seen_ms, count FROM rdp_logons \
                 WHERE last_seen_ms >= ?1 ORDER BY last_seen_ms DESC, addr",
            )?;
            let mut rows = stmt.query([since_ms])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                match row_to_logon(row) {
                    Ok(logon) => out.push(logon),
                    Err(error) => tracing::warn!(%error, "skipping unreadable rdp logon row"),
                }
            }
            Ok(out)
        })
    }

    /// Forgets addresses last seen before `older_than_ms`; returns how many.
    pub fn rdp_logons_prune(&self, older_than_ms: i64) -> Result<usize> {
        self.with(|conn| {
            Ok(conn.execute(
                "DELETE FROM rdp_logons WHERE last_seen_ms < ?1",
                [older_than_ms],
            )?)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn upsert_counts_and_tracks_times() {
        let s = mem();
        s.rdp_logon_record(ip("198.51.100.7"), 1_000).unwrap();
        s.rdp_logon_record(ip("198.51.100.7"), 3_000).unwrap();
        // An older event arriving late keeps last_seen but lowers first_seen.
        s.rdp_logon_record(ip("198.51.100.7"), 500).unwrap();
        let rows = s.rdp_logons_since(0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[0].first_seen_ms, 500);
        assert_eq!(rows[0].last_seen_ms, 3_000);
    }

    #[test]
    fn upsert_twice_is_one_row() {
        let s = mem();
        s.rdp_logon_record(ip("2001:db8::1"), 10).unwrap();
        s.rdp_logon_record(ip("2001:db8::1"), 10).unwrap();
        assert_eq!(s.rdp_logons_since(0).unwrap().len(), 1);
    }

    #[test]
    fn mapped_addresses_are_canonicalized() {
        let s = mem();
        s.rdp_logon_record(ip("1.2.3.4"), 1).unwrap();
        s.rdp_logon_record(ip("::ffff:1.2.3.4"), 2).unwrap();
        let rows = s.rdp_logons_since(0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].addr, ip("1.2.3.4"));
        assert_eq!(rows[0].count, 2);
    }

    #[test]
    fn since_filters_and_orders_and_prune() {
        let s = mem();
        s.rdp_logons_record_many(&[
            (ip("1.1.1.1"), 100),
            (ip("2.2.2.2"), 300),
            (ip("3.3.3.3"), 200),
        ])
        .unwrap();
        let addrs = |since| -> Vec<String> {
            s.rdp_logons_since(since)
                .unwrap()
                .iter()
                .map(|l| l.addr.to_string())
                .collect()
        };
        assert_eq!(addrs(0), ["2.2.2.2", "3.3.3.3", "1.1.1.1"]);
        assert_eq!(addrs(200), ["2.2.2.2", "3.3.3.3"]);
        assert_eq!(addrs(301), Vec::<String>::new());
        assert_eq!(s.rdp_logons_prune(200).unwrap(), 1);
        assert_eq!(addrs(0), ["2.2.2.2", "3.3.3.3"]);
        assert_eq!(s.rdp_logons_prune(200).unwrap(), 0);
        s.rdp_logons_record_many(&[]).unwrap();
    }

    #[test]
    fn table_is_bounded_dropping_least_recent() {
        let limits = Limits {
            rdp_logons_max: 5,
            ..Limits::default()
        };
        let s = Store::open_in_memory_with(limits).unwrap();
        let events: Vec<(IpAddr, i64)> = (0..20u8)
            .map(|i| (IpAddr::from([10, 0, 0, i]), i64::from(i)))
            .collect();
        s.rdp_logons_record_many(&events).unwrap();
        let rows = s.rdp_logons_since(0).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].addr, ip("10.0.0.19"));
        assert_eq!(rows[4].addr, ip("10.0.0.15"));
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        {
            let s = Store::open(&path).unwrap().store;
            s.rdp_logon_record(ip("9.9.9.9"), 42).unwrap();
        }
        let s = Store::open(&path).unwrap().store;
        assert_eq!(s.rdp_logons_since(0).unwrap()[0].last_seen_ms, 42);
    }
}
