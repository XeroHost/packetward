// SPDX-License-Identifier: GPL-3.0-or-later
//! Desired firewall blocks, persisted so they survive an agent restart.
//!
//! The firewall is reconciled from this table; the table is not the firewall. Expiry follows
//! `pw_firewall::split_expired`: a block whose `expires_ms` equals `now` is already expired.

use std::str::FromStr;

use pw_core::Cidr;
use rusqlite::{params, Row};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{to_i64, to_u64, Result, StoreError};
use crate::store::{clip, Store};

const MAX_REASON_BYTES: usize = 512;
const SOURCE_LIST_PREFIX: &str = "list:";

/// Where a block came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockSource {
    /// Added by an operator (UI or `pwctl`). Never relabelled by an automatic source.
    Manual,
    /// Added by the Guardian.
    Guardian,
    /// Added by an enabled blocklist; the string is the list id.
    List(String),
}

impl BlockSource {
    /// `manual`, `guardian` or `list:<id>`.
    pub fn as_db_string(&self) -> String {
        match self {
            Self::Manual => "manual".to_owned(),
            Self::Guardian => "guardian".to_owned(),
            Self::List(id) => format!("{SOURCE_LIST_PREFIX}{id}"),
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "manual" => Ok(Self::Manual),
            "guardian" => Ok(Self::Guardian),
            other => match other.strip_prefix(SOURCE_LIST_PREFIX) {
                Some(id) if !id.is_empty() => Ok(Self::List(id.to_owned())),
                _ => Err(StoreError::InvalidInput(format!(
                    "block source {other:?} (expected manual, guardian or list:<id>)"
                ))),
            },
        }
    }
}

impl Serialize for BlockSource {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_db_string())
    }
}

impl<'de> Deserialize<'de> for BlockSource {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

mod cidr_text {
    use super::*;

    pub fn serialize<S: Serializer>(c: &Cidr, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&c.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Cidr, D::Error> {
        let text = String::deserialize(d)?;
        Cidr::from_str(&text).map_err(serde::de::Error::custom)
    }
}

/// One desired block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    /// Canonical key: `1.2.3.4` and `1.2.3.4/32` are the same block.
    #[serde(with = "cidr_text")]
    pub cidr: Cidr,
    pub source: BlockSource,
    pub reason: String,
    pub created_ms: i64,
    /// `None` = never expires (manual blocks). Otherwise expired once `now_ms >= expires_ms`.
    pub expires_ms: Option<i64>,
    /// Packets/connections the firewall dropped from it, as reported by the engine.
    pub hits: u64,
    /// Guardian escalation step (0 = first offence); drives the next TTL.
    pub escalation_level: u32,
}

impl BlockRecord {
    pub fn new(
        cidr: Cidr,
        source: BlockSource,
        reason: impl Into<String>,
        created_ms: i64,
        expires_ms: Option<i64>,
    ) -> Self {
        Self {
            cidr,
            source,
            reason: reason.into(),
            created_ms,
            expires_ms,
            hits: 0,
            escalation_level: 0,
        }
    }

    /// Expired at `now_ms` (the boundary counts as expired).
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_ms.is_some_and(|e| e <= now_ms)
    }
}

const COLUMNS: &str = "cidr, source, reason, created_ms, expires_ms, hits, escalation_level";

fn row_to_block(row: &Row<'_>) -> Result<BlockRecord> {
    let cidr: String = row.get(0)?;
    let source: String = row.get(1)?;
    Ok(BlockRecord {
        cidr: Cidr::from_str(&cidr)
            .map_err(|e| StoreError::InvalidData(format!("stored block {cidr:?}: {e}")))?,
        source: BlockSource::parse(&source)
            .map_err(|_| StoreError::InvalidData(format!("stored block source {source:?}")))?,
        reason: row.get(2)?,
        created_ms: row.get(3)?,
        expires_ms: row.get(4)?,
        hits: to_u64(row.get(5)?, "block hits")?,
        escalation_level: u32::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
    })
}

fn collect(
    stmt: &mut rusqlite::Statement<'_>,
    params: impl rusqlite::Params,
) -> Result<Vec<BlockRecord>> {
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        // One unreadable row must not hide the rest of the blocks.
        match row_to_block(row) {
            Ok(block) => out.push(block),
            Err(error) => tracing::warn!(%error, "skipping unreadable block row"),
        }
    }
    Ok(out)
}

impl Store {
    /// Inserts a block, or merges it into the existing one for the same CIDR:
    ///
    /// * `created_ms` and `hits` of the existing row are kept;
    /// * `expires_ms`: never-expires wins, otherwise the later deadline wins (as
    ///   `pw_firewall::split_expired` does for duplicates);
    /// * `escalation_level`: the higher one;
    /// * `source`/`reason`: the new ones, except that a `manual` block is never relabelled by an
    ///   automatic source (it keeps its source and reason).
    ///
    /// Calling it twice with the same record is a no-op the second time.
    pub fn block_upsert(&self, block: &BlockRecord) -> Result<()> {
        let hits = to_i64(block.hits, "hits")?;
        let reason = clip(&block.reason, MAX_REASON_BYTES);
        self.with(|conn| {
            conn.execute(
                "INSERT INTO blocks(cidr, source, reason, created_ms, expires_ms, hits, escalation_level) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(cidr) DO UPDATE SET \
                   source = CASE WHEN blocks.source = 'manual' THEN blocks.source ELSE excluded.source END, \
                   reason = CASE WHEN blocks.source = 'manual' THEN blocks.reason ELSE excluded.reason END, \
                   expires_ms = CASE WHEN blocks.expires_ms IS NULL OR excluded.expires_ms IS NULL \
                                     THEN NULL ELSE max(blocks.expires_ms, excluded.expires_ms) END, \
                   escalation_level = max(blocks.escalation_level, excluded.escalation_level)",
                params![
                    block.cidr.to_string(),
                    block.source.as_db_string(),
                    reason,
                    block.created_ms,
                    block.expires_ms,
                    hits,
                    i64::from(block.escalation_level),
                ],
            )?;
            Ok(())
        })
    }

    /// Adds `n` to the hit counter; false if the block does not exist.
    pub fn block_add_hits(&self, cidr: &Cidr, n: u64) -> Result<bool> {
        let n = to_i64(n, "hits")?;
        self.with(|conn| {
            Ok(conn.execute(
                "UPDATE blocks SET hits = min(hits + ?2, 9223372036854775807) WHERE cidr = ?1",
                params![cidr.to_string(), n],
            )? > 0)
        })
    }

    pub fn block_get(&self, cidr: &Cidr) -> Result<Option<BlockRecord>> {
        self.with(|conn| {
            let mut stmt =
                conn.prepare_cached(&format!("SELECT {COLUMNS} FROM blocks WHERE cidr = ?1"))?;
            Ok(collect(&mut stmt, [cidr.to_string()])?.pop())
        })
    }

    /// Removes one block; true if it existed.
    pub fn block_remove(&self, cidr: &Cidr) -> Result<bool> {
        self.with(|conn| {
            Ok(conn.execute("DELETE FROM blocks WHERE cidr = ?1", [cidr.to_string()])? > 0)
        })
    }

    /// Removes every block of one source (a blocklist refresh, disabling a list); returns how many.
    pub fn blocks_remove_source(&self, source: &BlockSource) -> Result<usize> {
        self.with(|conn| {
            Ok(conn.execute(
                "DELETE FROM blocks WHERE source = ?1",
                [source.as_db_string()],
            )?)
        })
    }

    /// Blocks that have not expired at `now_ms`, oldest first.
    pub fn blocks_list_active(&self, now_ms: i64) -> Result<Vec<BlockRecord>> {
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM blocks \
                 WHERE expires_ms IS NULL OR expires_ms > ?1 \
                 ORDER BY created_ms, cidr"
            ))?;
            collect(&mut stmt, [now_ms])
        })
    }

    /// Deletes the blocks expired at `now_ms` (`expires_ms <= now_ms`) and returns them, soonest
    /// expiry first, so the caller can remove their firewall rules and audit the expiry.
    pub fn blocks_expire(&self, now_ms: i64) -> Result<Vec<BlockRecord>> {
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "DELETE FROM blocks WHERE expires_ms IS NOT NULL AND expires_ms <= ?1 \
                 RETURNING {COLUMNS}"
            ))?;
            let mut expired = collect(&mut stmt, [now_ms])?;
            expired.sort_by_key(|b| (b.expires_ms, b.created_ms));
            Ok(expired)
        })
    }

    /// Removes every block (`pwctl unblock --all`); returns how many.
    pub fn blocks_clear_all(&self) -> Result<usize> {
        self.with(|conn| Ok(conn.execute("DELETE FROM blocks", [])?))
    }

    /// Rows in the table, expired or not.
    pub fn blocks_count(&self) -> Result<u64> {
        self.with(|conn| {
            let n: i64 = conn.query_row("SELECT count(*) FROM blocks", [], |r| r.get(0))?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    fn block(text: &str, source: BlockSource, expires: Option<i64>) -> BlockRecord {
        BlockRecord::new(cidr(text), source, "because", 1_000, expires)
    }

    #[test]
    fn upsert_get_remove() {
        let s = mem();
        let b = block("203.0.113.9", BlockSource::Guardian, Some(5_000));
        s.block_upsert(&b).unwrap();
        assert_eq!(s.block_get(&cidr("203.0.113.9/32")).unwrap(), Some(b));
        assert!(s.block_remove(&cidr("203.0.113.9")).unwrap());
        assert!(!s.block_remove(&cidr("203.0.113.9")).unwrap());
        assert_eq!(s.block_get(&cidr("203.0.113.9")).unwrap(), None);
    }

    #[test]
    fn bare_address_and_host_prefix_are_the_same_row() {
        let s = mem();
        s.block_upsert(&block("1.2.3.4", BlockSource::Manual, None))
            .unwrap();
        s.block_upsert(&block("1.2.3.4/32", BlockSource::Manual, None))
            .unwrap();
        // Host bits are normalized away too.
        s.block_upsert(&block("10.1.2.3/24", BlockSource::Manual, None))
            .unwrap();
        s.block_upsert(&block("10.1.2.0/24", BlockSource::Manual, None))
            .unwrap();
        assert_eq!(s.blocks_count().unwrap(), 2);
        // IPv4-mapped IPv6 is canonicalized by Cidr.
        s.block_upsert(&block("::ffff:1.2.3.4", BlockSource::Manual, None))
            .unwrap();
        assert_eq!(s.blocks_count().unwrap(), 2);
    }

    #[test]
    fn upsert_is_idempotent() {
        let s = mem();
        let b = block("1.2.3.4", BlockSource::Guardian, Some(9_000));
        s.block_upsert(&b).unwrap();
        s.block_upsert(&b).unwrap();
        assert_eq!(s.blocks_count().unwrap(), 1);
        assert_eq!(s.block_get(&b.cidr).unwrap().unwrap(), b);
    }

    #[test]
    fn upsert_merge_rules() {
        let s = mem();
        let c = cidr("1.2.3.4");
        let mut first = block("1.2.3.4", BlockSource::Guardian, Some(5_000));
        first.escalation_level = 2;
        s.block_upsert(&first).unwrap();
        s.block_add_hits(&c, 7).unwrap();

        // Later expiry wins, lower escalation does not downgrade, created/hits are kept.
        let mut again = block("1.2.3.4", BlockSource::Guardian, Some(9_000));
        again.created_ms = 4_000;
        again.escalation_level = 1;
        s.block_upsert(&again).unwrap();
        let got = s.block_get(&c).unwrap().unwrap();
        assert_eq!(got.expires_ms, Some(9_000));
        assert_eq!(got.escalation_level, 2);
        assert_eq!(got.created_ms, 1_000);
        assert_eq!(got.hits, 7);

        // An earlier deadline does not shorten an existing block.
        s.block_upsert(&block("1.2.3.4", BlockSource::Guardian, Some(2_000)))
            .unwrap();
        assert_eq!(s.block_get(&c).unwrap().unwrap().expires_ms, Some(9_000));

        // Never-expires wins, in both directions.
        s.block_upsert(&block("1.2.3.4", BlockSource::Manual, None))
            .unwrap();
        assert_eq!(s.block_get(&c).unwrap().unwrap().expires_ms, None);
        s.block_upsert(&block("1.2.3.4", BlockSource::Guardian, Some(2_000)))
            .unwrap();
        assert_eq!(s.block_get(&c).unwrap().unwrap().expires_ms, None);
    }

    #[test]
    fn manual_source_and_reason_are_not_relabelled() {
        let s = mem();
        let c = cidr("1.2.3.4");
        let mut manual = block("1.2.3.4", BlockSource::Manual, None);
        manual.reason = "operator said so".into();
        s.block_upsert(&manual).unwrap();
        let mut auto = block("1.2.3.4", BlockSource::Guardian, Some(100));
        auto.reason = "syn flood".into();
        s.block_upsert(&auto).unwrap();
        let got = s.block_get(&c).unwrap().unwrap();
        assert_eq!(got.source, BlockSource::Manual);
        assert_eq!(got.reason, "operator said so");

        // ...but an automatic block is relabelled by a later manual one.
        let d = cidr("5.6.7.8");
        s.block_upsert(&block("5.6.7.8", BlockSource::Guardian, Some(100)))
            .unwrap();
        s.block_upsert(&block("5.6.7.8", BlockSource::Manual, None))
            .unwrap();
        assert_eq!(
            s.block_get(&d).unwrap().unwrap().source,
            BlockSource::Manual
        );
    }

    #[test]
    fn expiry_boundary_matches_firewall_semantics() {
        let s = mem();
        s.block_upsert(&block("1.1.1.1", BlockSource::Guardian, Some(100)))
            .unwrap();
        s.block_upsert(&block("2.2.2.2", BlockSource::Guardian, Some(200)))
            .unwrap();
        s.block_upsert(&block("3.3.3.3", BlockSource::Manual, None))
            .unwrap();

        let at = |now| -> Vec<String> {
            s.blocks_list_active(now)
                .unwrap()
                .iter()
                .map(|b| b.cidr.to_string())
                .collect()
        };
        assert_eq!(at(99).len(), 3);
        // Exactly at the deadline the block is expired.
        assert_eq!(at(100), ["2.2.2.2/32", "3.3.3.3/32"]);
        assert_eq!(at(200), ["3.3.3.3/32"]);
        assert_eq!(at(i64::MAX), ["3.3.3.3/32"]);

        // Nothing expired yet.
        assert!(s.blocks_expire(99).unwrap().is_empty());
        let expired = s.blocks_expire(150).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].cidr, cidr("1.1.1.1"));
        // Returned once only, and gone from the table.
        assert!(s.blocks_expire(150).unwrap().is_empty());
        assert_eq!(s.blocks_count().unwrap(), 2);
        let expired = s.blocks_expire(200).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(s.blocks_count().unwrap(), 1);
        // A never-expiring block is untouched.
        assert!(s.blocks_expire(i64::MAX).unwrap().is_empty());
    }

    #[test]
    fn expire_returns_soonest_first() {
        let s = mem();
        for (c, e) in [("1.1.1.1", 30), ("2.2.2.2", 10), ("3.3.3.3", 20)] {
            s.block_upsert(&block(c, BlockSource::Guardian, Some(e)))
                .unwrap();
        }
        let order: Vec<i64> = s
            .blocks_expire(100)
            .unwrap()
            .iter()
            .filter_map(|b| b.expires_ms)
            .collect();
        assert_eq!(order, [10, 20, 30]);
    }

    #[test]
    fn hits_accumulate_and_saturate() {
        let s = mem();
        let c = cidr("1.2.3.4");
        assert!(!s.block_add_hits(&c, 1).unwrap());
        s.block_upsert(&block("1.2.3.4", BlockSource::Guardian, None))
            .unwrap();
        s.block_add_hits(&c, 5).unwrap();
        s.block_add_hits(&c, 6).unwrap();
        assert_eq!(s.block_get(&c).unwrap().unwrap().hits, 11);
        s.block_add_hits(&c, i64::MAX as u64).unwrap();
        s.block_add_hits(&c, i64::MAX as u64).unwrap();
        assert_eq!(s.block_get(&c).unwrap().unwrap().hits, i64::MAX as u64);
        assert!(s.block_add_hits(&c, u64::MAX).is_err());
    }

    #[test]
    fn clear_all_and_remove_by_source() {
        let s = mem();
        s.block_upsert(&block(
            "1.1.1.1",
            BlockSource::List("spamhaus".into()),
            None,
        ))
        .unwrap();
        s.block_upsert(&block(
            "2.2.2.2",
            BlockSource::List("spamhaus".into()),
            None,
        ))
        .unwrap();
        s.block_upsert(&block("3.3.3.3", BlockSource::List("other".into()), None))
            .unwrap();
        s.block_upsert(&block("4.4.4.4", BlockSource::Manual, None))
            .unwrap();
        assert_eq!(
            s.blocks_remove_source(&BlockSource::List("spamhaus".into()))
                .unwrap(),
            2
        );
        assert_eq!(s.blocks_count().unwrap(), 2);
        assert_eq!(s.blocks_clear_all().unwrap(), 2);
        assert_eq!(s.blocks_count().unwrap(), 0);
        assert_eq!(s.blocks_clear_all().unwrap(), 0);
    }

    #[test]
    fn source_parsing_and_serde() {
        assert_eq!(BlockSource::parse("manual").unwrap(), BlockSource::Manual);
        assert_eq!(
            BlockSource::parse("list:x:y").unwrap(),
            BlockSource::List("x:y".into())
        );
        assert!(BlockSource::parse("list:").is_err());
        assert!(BlockSource::parse("nonsense").is_err());
        let b = block("1.2.3.0/24", BlockSource::List("abc".into()), Some(5));
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains(r#""source":"list:abc""#), "{json}");
        assert!(json.contains(r#""cidr":"1.2.3.0/24""#), "{json}");
        assert_eq!(serde_json::from_str::<BlockRecord>(&json).unwrap(), b);
    }

    #[test]
    fn ipv6_and_hostile_reason() {
        let s = mem();
        let mut b = block("2001:db8::/32", BlockSource::Guardian, None);
        b.reason = "x'); DROP TABLE blocks;-- \0 end".into();
        s.block_upsert(&b).unwrap();
        assert_eq!(s.block_get(&b.cidr).unwrap().unwrap().reason, b.reason);
        b.cidr = cidr("2001:db8:1::/48");
        b.reason = "é".repeat(10_000);
        s.block_upsert(&b).unwrap();
        let got = s.block_get(&b.cidr).unwrap().unwrap();
        assert!(got.reason.len() <= MAX_REASON_BYTES);
        assert_eq!(s.blocks_count().unwrap(), 2);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        let b = block("198.51.100.0/24", BlockSource::Guardian, Some(5_000));
        {
            let s = Store::open(&path).unwrap().store;
            s.block_upsert(&b).unwrap();
        }
        let s = Store::open(&path).unwrap().store;
        assert_eq!(s.blocks_list_active(0).unwrap(), vec![b]);
    }
}
