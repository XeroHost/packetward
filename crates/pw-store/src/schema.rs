// SPDX-License-Identifier: GPL-3.0-or-later
//! Schema and the forward-only migration list.
//!
//! `PRAGMA user_version` is the number of migrations applied. Never edit or reorder an entry that
//! has shipped: append a new one. Each step runs in its own `IMMEDIATE` transaction together with
//! the version bump, so a failed step leaves the database exactly as it was.

use rusqlite::{Connection, TransactionBehavior};

use crate::error::{Result, StoreError};

/// Migration 1: audit log, key/value settings, desired blocks.
const V1_CORE: &str = "
CREATE TABLE audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms   INTEGER NOT NULL,
    actor   TEXT    NOT NULL,
    action  TEXT    NOT NULL,
    target  TEXT    NOT NULL,
    detail  TEXT    NOT NULL,
    result  TEXT    NOT NULL
);
CREATE INDEX idx_audit_ts        ON audit(ts_ms);
CREATE INDEX idx_audit_action_ts ON audit(action, ts_ms);
CREATE INDEX idx_audit_target_ts ON audit(target, ts_ms);
CREATE INDEX idx_audit_actor_ts  ON audit(actor, ts_ms);

CREATE TABLE kv (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_ms INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE blocks (
    cidr             TEXT    PRIMARY KEY,
    source           TEXT    NOT NULL,
    reason           TEXT    NOT NULL,
    created_ms       INTEGER NOT NULL,
    expires_ms       INTEGER,
    hits             INTEGER NOT NULL DEFAULT 0,
    escalation_level INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX idx_blocks_expires ON blocks(expires_ms);
CREATE INDEX idx_blocks_source  ON blocks(source);
";

/// Migration 2: alert inbox and the trusted RDP logon addresses.
const V2_ALERTS_RDP: &str = "
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY,
    kind          TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    source        TEXT,
    summary_key   TEXT    NOT NULL,
    metrics       TEXT    NOT NULL,
    window_secs   INTEGER NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    protected     INTEGER NOT NULL,
    peak_severity TEXT    NOT NULL,
    phase         TEXT    NOT NULL
);
CREATE INDEX idx_alerts_last_seen ON alerts(last_seen_ms);
CREATE INDEX idx_alerts_phase_last_seen ON alerts(phase, last_seen_ms);

CREATE TABLE rdp_logons (
    addr          TEXT    PRIMARY KEY,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    count         INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX idx_rdp_logons_last_seen ON rdp_logons(last_seen_ms);
";

/// Migration 3: cache of intelligence lookups (reverse DNS, ASN, AbuseIPDB...).
const V3_INTEL_CACHE: &str = "
CREATE TABLE intel_cache (
    ns         TEXT    NOT NULL,
    key        TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    expires_ms INTEGER NOT NULL,
    PRIMARY KEY (ns, key)
) WITHOUT ROWID;
CREATE INDEX idx_intel_cache_expires ON intel_cache(expires_ms);
";

/// The migrations, in order. `MIGRATIONS[n - 1]` brings the schema from version `n - 1` to `n`.
pub(crate) const MIGRATIONS: &[&str] = &[V1_CORE, V2_ALERTS_RDP, V3_INTEL_CACHE];

/// The schema version of this build.
pub const SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

pub(crate) fn user_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
}

/// Brings `conn` to `steps.len()`. Refuses a newer database before changing anything.
pub(crate) fn migrate(conn: &mut Connection, steps: &[&str]) -> Result<()> {
    let latest = steps.len() as i64;
    let current = user_version(conn)?;
    if current > latest {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: latest,
        });
    }
    for (index, sql) in steps.iter().enumerate().skip(current.max(0) as usize) {
        let target = index as i64 + 1;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Another process may have migrated while we waited for the write lock.
        if user_version(&tx)? >= target {
            continue;
        }
        tx.execute_batch(sql)
            .map_err(|source| StoreError::Migration {
                version: target,
                source,
            })?;
        tx.pragma_update(None, "user_version", target)
            .map_err(|source| StoreError::Migration {
                version: target,
                source,
            })?;
        tx.commit()?;
        tracing::info!(version = target, "store schema migrated");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn fresh_database_reaches_latest() {
        let mut conn = fresh();
        migrate(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
        for table in [
            "audit",
            "kv",
            "blocks",
            "alerts",
            "rdp_logons",
            "intel_cache",
        ] {
            let n: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "{table} missing");
        }
    }

    #[test]
    fn migrate_is_idempotent() {
        let mut conn = fresh();
        migrate(&mut conn, MIGRATIONS).unwrap();
        migrate(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_is_refused_without_changes() {
        let mut conn = fresh();
        migrate(&mut conn, MIGRATIONS).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 4)
            .unwrap();
        match migrate(&mut conn, MIGRATIONS) {
            Err(StoreError::SchemaTooNew { found, supported }) => {
                assert_eq!(found, SCHEMA_VERSION + 4);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION + 4);
    }

    #[test]
    fn failed_step_rolls_back_and_keeps_version() {
        let mut conn = fresh();
        let broken: &[&str] = &[
            "CREATE TABLE a (x INTEGER);",
            // The first statement succeeds, the second fails: the table must not survive.
            "CREATE TABLE b (x INTEGER); INSERT INTO missing_table VALUES (1);",
        ];
        match migrate(&mut conn, broken) {
            Err(StoreError::Migration { version: 2, .. }) => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(user_version(&conn).unwrap(), 1);
        let b: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='b'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(b, 0, "failed migration left a table behind");
        // The first step stays applied and a fixed list resumes from there.
        let fixed: &[&str] = &["CREATE TABLE a (x INTEGER);", "CREATE TABLE b (x INTEGER);"];
        migrate(&mut conn, fixed).unwrap();
        assert_eq!(user_version(&conn).unwrap(), 2);
    }

    /// Simulates a database left by every historical release: apply the first `k` migrations raw,
    /// seed what that version could hold, then open it with the current code.
    #[test]
    fn upgrade_from_every_historical_version() {
        for k in 0..=MIGRATIONS.len() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pw.db");
            {
                let conn = Connection::open(&path).unwrap();
                for (i, sql) in MIGRATIONS.iter().take(k).enumerate() {
                    conn.execute_batch(sql).unwrap();
                    conn.pragma_update(None, "user_version", i as i64 + 1)
                        .unwrap();
                }
                if k >= 1 {
                    conn.execute(
                        "INSERT INTO audit(ts_ms,actor,action,target,detail,result) \
                         VALUES (1,'agent','block','1.2.3.4/32','{}','ok')",
                        [],
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO kv(key,value,updated_ms) VALUES ('allowlist','[\"10.0.0.0/8\"]',1)",
                        [],
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO blocks(cidr,source,reason,created_ms,expires_ms) \
                         VALUES ('1.2.3.4/32','manual','test',1,NULL)",
                        [],
                    )
                    .unwrap();
                }
                if k >= 2 {
                    conn.execute(
                        "INSERT INTO alerts VALUES (7,'syn_flood','high',NULL,'syn_flood','[]',10,1,2,0,'high','ended')",
                        [],
                    )
                    .unwrap();
                    conn.execute("INSERT INTO rdp_logons VALUES ('9.9.9.9',1,2,3)", [])
                        .unwrap();
                }
                if k >= 3 {
                    conn.execute(
                        "INSERT INTO intel_cache VALUES ('rdns','1.2.3.4','\"h\"',99)",
                        [],
                    )
                    .unwrap();
                }
            }
            let opened = crate::Store::open(&path).unwrap();
            assert!(!opened.was_recovered(), "k={k}");
            let store = opened.store;
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION, "k={k}");
            if k >= 1 {
                assert_eq!(store.audit_count().unwrap(), 1, "k={k}");
                assert!(store
                    .kv_get::<Vec<String>>("allowlist")
                    .unwrap()
                    .is_some_and(|v| v == ["10.0.0.0/8"]));
                assert_eq!(store.blocks_count().unwrap(), 1, "k={k}");
            }
            if k >= 2 {
                assert_eq!(store.alerts_recent(10).unwrap().len(), 1, "k={k}");
                assert_eq!(store.rdp_logons_since(0).unwrap().len(), 1, "k={k}");
            }
            if k >= 3 {
                let hit: Option<String> = store.cache_get("rdns", "1.2.3.4", 0).unwrap();
                assert_eq!(hit.as_deref(), Some("h"), "k={k}");
            }
            // All tables are usable after the upgrade.
            let none: Option<String> = store.cache_get("x", "y", 0).unwrap();
            assert!(none.is_none());
            assert_eq!(store.alerts_recent(10).unwrap().len(), usize::from(k >= 2));
        }
    }
}
