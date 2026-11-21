// SPDX-License-Identifier: GPL-3.0-or-later
//! Append-only audit log of security-relevant actions.

use std::sync::atomic::Ordering;

use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, StoreError};
use crate::store::{clip, Store};

/// Longest `action` kept (bytes); longer text is cut on a character boundary.
pub const MAX_ACTION_BYTES: usize = 128;
/// Longest `target` kept (bytes).
pub const MAX_TARGET_BYTES: usize = 1024;
/// Largest `detail` JSON kept (bytes); a bigger one is replaced by `{"truncated":true,"bytes":N}`.
pub const MAX_DETAIL_BYTES: usize = 64 * 1024;
/// Most rows one query returns.
pub const MAX_QUERY_LIMIT: usize = 10_000;

/// Who did it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    Agent,
    Ui,
    Pwctl,
    Guardian,
    RdpShield,
    Blocklist,
    /// An AI client through the MCP server (ARCHITECTURE 6.14): every call, reads included.
    Mcp,
}

impl AuditActor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Ui => "ui",
            Self::Pwctl => "pwctl",
            Self::Guardian => "guardian",
            Self::RdpShield => "rdp_shield",
            Self::Blocklist => "blocklist",
            Self::Mcp => "mcp",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "agent" => Self::Agent,
            "ui" => Self::Ui,
            "pwctl" => Self::Pwctl,
            "guardian" => Self::Guardian,
            "rdp_shield" => Self::RdpShield,
            "blocklist" => Self::Blocklist,
            "mcp" => Self::Mcp,
            other => return Err(StoreError::InvalidData(format!("audit actor {other:?}"))),
        })
    }
}

/// How it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Ok,
    /// Policy said no (protected address, circuit breaker...).
    Refused,
    Failed,
}

impl AuditResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "ok" => Self::Ok,
            "refused" => Self::Refused,
            "failed" => Self::Failed,
            other => return Err(StoreError::InvalidData(format!("audit result {other:?}"))),
        })
    }
}

/// An event to append.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewAudit {
    pub ts_ms: i64,
    pub actor: AuditActor,
    /// Key such as `block`, `unblock`, `purge`, `guardian_mode`, `rdp_restrict`, `rdp_revert`.
    pub action: String,
    /// What it acted on: an IP/CIDR, a rule name...
    pub target: String,
    pub detail: Value,
    pub result: AuditResult,
}

impl NewAudit {
    pub fn new(
        ts_ms: i64,
        actor: AuditActor,
        action: impl Into<String>,
        target: impl Into<String>,
        result: AuditResult,
    ) -> Self {
        Self {
            ts_ms,
            actor,
            action: action.into(),
            target: target.into(),
            detail: Value::Null,
            result,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }
}

/// A stored audit row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts_ms: i64,
    pub actor: AuditActor,
    pub action: String,
    pub target: String,
    pub detail: Value,
    pub result: AuditResult,
}

/// Filters for [`Store::audit_query`]. Newest first.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AuditQuery {
    /// Only rows with `ts_ms >= since_ms`.
    pub since_ms: Option<i64>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub actor: Option<AuditActor>,
    pub result: Option<AuditResult>,
    /// Capped at [`MAX_QUERY_LIMIT`].
    pub limit: usize,
}

impl AuditQuery {
    pub fn recent(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }
}

fn row_to_entry(row: &Row<'_>) -> Result<AuditEntry> {
    let detail_text: String = row.get(5)?;
    let actor: String = row.get(2)?;
    let result: String = row.get(6)?;
    Ok(AuditEntry {
        id: row.get(0)?,
        ts_ms: row.get(1)?,
        actor: AuditActor::parse(&actor)?,
        action: row.get(3)?,
        target: row.get(4)?,
        // A detail we cannot parse is still evidence: keep it as a string.
        detail: serde_json::from_str(&detail_text).unwrap_or(Value::String(detail_text)),
        result: AuditResult::parse(&result)?,
    })
}

/// The SELECT for a query with its positional parameters. Values are only ever bound, never
/// spliced into the SQL (the limit is a clamped integer).
fn build_query(query: &AuditQuery) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        "SELECT id, ts_ms, actor, action, target, detail, result FROM audit WHERE 1=1",
    );
    let mut args: Vec<SqlValue> = Vec::new();
    let mut add = |clause: &str, value: SqlValue| {
        args.push(value);
        sql.push_str(&format!(" AND {clause} ?{}", args.len()));
    };
    if let Some(since) = query.since_ms {
        add("ts_ms >=", SqlValue::Integer(since));
    }
    if let Some(action) = &query.action {
        add("action =", SqlValue::Text(action.clone()));
    }
    if let Some(target) = &query.target {
        add("target =", SqlValue::Text(target.clone()));
    }
    if let Some(actor) = query.actor {
        add("actor =", SqlValue::Text(actor.as_str().to_owned()));
    }
    if let Some(result) = query.result {
        add("result =", SqlValue::Text(result.as_str().to_owned()));
    }
    let limit = query.limit.min(MAX_QUERY_LIMIT);
    sql.push_str(&format!(" ORDER BY ts_ms DESC, id DESC LIMIT {limit}"));
    (sql, args)
}

/// Deletes by age and by row cap; returns how many rows went.
fn prune(conn: &Connection, retention_ms: i64, max_rows: u64, now_ms: i64) -> Result<usize> {
    let mut removed = conn.execute(
        "DELETE FROM audit WHERE ts_ms < ?1",
        [now_ms.saturating_sub(retention_ms)],
    )?;
    let max_rows = i64::try_from(max_rows).unwrap_or(i64::MAX);
    // Rows are ordered by id (append order); everything beyond the newest `max_rows` goes.
    removed += conn.execute(
        "DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?1)",
        [max_rows],
    )?;
    Ok(removed)
}

impl Store {
    /// Appends one event and returns its id. `action` and `target` are clipped to
    /// [`MAX_ACTION_BYTES`] / [`MAX_TARGET_BYTES`] and an oversized `detail` is replaced by a
    /// marker, so a hostile value can neither fail the write nor bloat the file.
    ///
    /// Retention (`Limits::audit_retention_ms` relative to `event.ts_ms`, `audit_max_rows`) is
    /// enforced every `Limits::prune_every` appends.
    pub fn audit_append(&self, event: &NewAudit) -> Result<i64> {
        let mut detail = serde_json::to_string(&event.detail)?;
        if detail.len() > MAX_DETAIL_BYTES {
            detail = format!(r#"{{"truncated":true,"bytes":{}}}"#, detail.len());
        }
        let action = clip(&event.action, MAX_ACTION_BYTES);
        let target = clip(&event.target, MAX_TARGET_BYTES);
        let nth = self.audit_appends.fetch_add(1, Ordering::Relaxed) + 1;
        let prune_now = nth.is_multiple_of(self.limits.prune_every.max(1));
        self.with(|conn| {
            conn.execute(
                "INSERT INTO audit(ts_ms, actor, action, target, detail, result) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    event.ts_ms,
                    event.actor.as_str(),
                    action,
                    target,
                    detail,
                    event.result.as_str()
                ],
            )?;
            let id = conn.last_insert_rowid();
            if prune_now {
                let removed = prune(
                    conn,
                    self.limits.audit_retention_ms,
                    self.limits.audit_max_rows,
                    event.ts_ms,
                )?;
                if removed > 0 {
                    tracing::debug!(removed, "audit log pruned");
                }
            }
            Ok(id)
        })
    }

    /// Matching rows, newest first (`ts_ms`, then `id`).
    pub fn audit_query(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let (sql, args) = build_query(query);
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(&sql)?;
            let mut rows = stmt.query(params_from_iter(args.iter()))?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(row_to_entry(row)?);
            }
            Ok(out)
        })
    }

    /// Deletes rows with `ts_ms < older_than_ms`; returns how many.
    pub fn audit_prune(&self, older_than_ms: i64) -> Result<usize> {
        self.with(|conn| Ok(conn.execute("DELETE FROM audit WHERE ts_ms < ?1", [older_than_ms])?))
    }

    /// Number of audit rows.
    pub fn audit_count(&self) -> Result<u64> {
        self.with(|conn| {
            let n: i64 = conn.query_row("SELECT count(*) FROM audit", [], |r| r.get(0))?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// The query plan of [`Store::audit_query`] for `query` (diagnostics and tests).
    #[cfg(test)]
    fn audit_query_plan(&self, query: &AuditQuery) -> String {
        let (sql, args) = build_query(query);
        self.with(|conn| {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
            let rows = stmt.query_map(params_from_iter(args.iter()), |r| r.get::<_, String>(3))?;
            Ok(rows
                .collect::<std::result::Result<Vec<_>, _>>()?
                .join(" | "))
        })
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;
    use serde_json::json;
    use std::time::Instant;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn event(ts: i64, action: &str, target: &str) -> NewAudit {
        NewAudit::new(ts, AuditActor::Agent, action, target, AuditResult::Ok)
    }

    #[test]
    fn append_and_query_roundtrip() {
        let s = mem();
        let id = s
            .audit_append(
                &NewAudit::new(
                    1_000,
                    AuditActor::Guardian,
                    "block",
                    "203.0.113.7/32",
                    AuditResult::Refused,
                )
                .with_detail(json!({"reason": "protected", "n": 3})),
            )
            .unwrap();
        let rows = s.audit_query(&AuditQuery::recent(10)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].actor, AuditActor::Guardian);
        assert_eq!(rows[0].result, AuditResult::Refused);
        assert_eq!(rows[0].detail["reason"], "protected");
        assert_eq!(rows[0].detail["n"], 3);
    }

    #[test]
    fn the_mcp_actor_round_trips_through_the_store() {
        let s = mem();
        s.audit_append(&NewAudit::new(
            1_000,
            AuditActor::Mcp,
            "block_ip",
            "203.0.113.7",
            AuditResult::Ok,
        ))
        .unwrap();
        let rows = s.audit_query(&AuditQuery::recent(10)).unwrap();
        assert_eq!(rows[0].actor, AuditActor::Mcp);
        assert_eq!(rows[0].actor.as_str(), "mcp");
        let filtered = s
            .audit_query(&AuditQuery {
                actor: Some(AuditActor::Mcp),
                ..AuditQuery::recent(10)
            })
            .unwrap();
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn query_filters_and_order() {
        let s = mem();
        s.audit_append(&event(10, "block", "a")).unwrap();
        s.audit_append(&event(20, "unblock", "a")).unwrap();
        s.audit_append(&NewAudit::new(
            30,
            AuditActor::Ui,
            "block",
            "b",
            AuditResult::Failed,
        ))
        .unwrap();
        s.audit_append(&event(30, "block", "c")).unwrap();

        let all = s.audit_query(&AuditQuery::recent(10)).unwrap();
        let order: Vec<&str> = all.iter().map(|e| e.target.as_str()).collect();
        // Newest first; the tie at ts=30 is broken by id (newer id first).
        assert_eq!(order, ["c", "b", "a", "a"]);

        let q = AuditQuery {
            action: Some("block".into()),
            ..AuditQuery::recent(10)
        };
        assert_eq!(s.audit_query(&q).unwrap().len(), 3);
        let q = AuditQuery {
            target: Some("a".into()),
            ..AuditQuery::recent(10)
        };
        assert_eq!(s.audit_query(&q).unwrap().len(), 2);
        let q = AuditQuery {
            actor: Some(AuditActor::Ui),
            ..AuditQuery::recent(10)
        };
        assert_eq!(s.audit_query(&q).unwrap()[0].target, "b");
        let q = AuditQuery {
            result: Some(AuditResult::Failed),
            ..AuditQuery::recent(10)
        };
        assert_eq!(s.audit_query(&q).unwrap().len(), 1);
        let q = AuditQuery {
            since_ms: Some(20),
            ..AuditQuery::recent(10)
        };
        assert_eq!(s.audit_query(&q).unwrap().len(), 3);
        let q = AuditQuery {
            since_ms: Some(20),
            action: Some("block".into()),
            actor: Some(AuditActor::Agent),
            ..AuditQuery::recent(10)
        };
        assert_eq!(s.audit_query(&q).unwrap().len(), 1);
        assert_eq!(s.audit_query(&AuditQuery::recent(2)).unwrap().len(), 2);
        assert!(s.audit_query(&AuditQuery::recent(0)).unwrap().is_empty());
    }

    #[test]
    fn prune_by_age() {
        let s = mem();
        for ts in [1, 2, 3, 4, 5] {
            s.audit_append(&event(ts, "x", "t")).unwrap();
        }
        assert_eq!(s.audit_prune(3).unwrap(), 2);
        assert_eq!(s.audit_count().unwrap(), 3);
        assert_eq!(s.audit_prune(3).unwrap(), 0);
    }

    #[test]
    fn automatic_retention_by_age_and_rows() {
        let day = 24 * 3_600 * 1_000;
        let limits = Limits {
            audit_retention_ms: 90 * day,
            audit_max_rows: 50,
            prune_every: 1,
            ..Limits::default()
        };
        let s = Store::open_in_memory_with(limits).unwrap();
        // 100 days old, then recent: the old row goes by age on the next append.
        s.audit_append(&event(0, "old", "t")).unwrap();
        s.audit_append(&event(100 * day, "new", "t")).unwrap();
        let rows = s.audit_query(&AuditQuery::recent(10)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "new");
        // Row cap: never more than 50, newest kept.
        for i in 0..200 {
            s.audit_append(&event(100 * day + i, "bulk", &i.to_string()))
                .unwrap();
        }
        assert_eq!(s.audit_count().unwrap(), 50);
        let newest = s.audit_query(&AuditQuery::recent(1)).unwrap();
        assert_eq!(newest[0].target, "199");
        let oldest = s.audit_query(&AuditQuery::recent(50)).unwrap();
        assert_eq!(oldest.last().unwrap().target, "150");
    }

    #[test]
    fn default_limits_match_the_spec() {
        let l = Limits::default();
        assert_eq!(l.audit_retention_ms, 90 * 24 * 3600 * 1000);
        assert_eq!(l.audit_max_rows, 200_000);
    }

    #[test]
    fn ids_are_never_reused_after_pruning() {
        let s = mem();
        let a = s.audit_append(&event(1, "x", "t")).unwrap();
        s.audit_prune(100).unwrap();
        let b = s.audit_append(&event(200, "x", "t")).unwrap();
        assert!(b > a);
    }

    #[test]
    fn hostile_values_are_stored_verbatim_or_clipped() {
        let s = mem();
        let nasty = "'; DROP TABLE audit; --";
        let with_nul = "a\0b\0c";
        s.audit_append(
            &NewAudit::new(1, AuditActor::Ui, nasty, with_nul, AuditResult::Ok)
                .with_detail(json!({"q": nasty, "nul": with_nul})),
        )
        .unwrap();
        let rows = s.audit_query(&AuditQuery::recent(5)).unwrap();
        assert_eq!(rows[0].action, nasty);
        assert_eq!(rows[0].target, with_nul);
        assert_eq!(rows[0].detail["nul"], with_nul);
        // Filtering by hostile text is parameterized too.
        let q = AuditQuery {
            action: Some(nasty.into()),
            target: Some(with_nul.into()),
            ..AuditQuery::recent(5)
        };
        assert_eq!(s.audit_query(&q).unwrap().len(), 1);
        // The table is still there.
        assert_eq!(s.audit_count().unwrap(), 1);

        // Very long strings are clipped, never an error.
        let huge = "é".repeat(2_000_000);
        s.audit_append(
            &NewAudit::new(
                2,
                AuditActor::Ui,
                huge.clone(),
                huge.clone(),
                AuditResult::Ok,
            )
            .with_detail(json!({ "big": huge })),
        )
        .unwrap();
        let rows = s.audit_query(&AuditQuery::recent(1)).unwrap();
        assert!(rows[0].action.len() <= MAX_ACTION_BYTES);
        assert!(rows[0].target.len() <= MAX_TARGET_BYTES);
        assert_eq!(rows[0].detail["truncated"], true);
    }

    #[test]
    fn query_sql_is_not_injectable_through_filters_or_limit() {
        let s = mem();
        s.audit_append(&event(1, "x", "t")).unwrap();
        let q = AuditQuery {
            action: Some("x' OR '1'='1".into()),
            ..AuditQuery::recent(usize::MAX)
        };
        assert!(s.audit_query(&q).unwrap().is_empty());
        // usize::MAX limit is clamped, not an error.
        assert_eq!(
            s.audit_query(&AuditQuery::recent(usize::MAX))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn query_over_100k_rows_uses_indexes_and_is_fast() {
        let s = mem();
        s.with(|conn| {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO audit(ts_ms, actor, action, target, detail, result) \
                     VALUES (?1, 'agent', ?2, ?3, '{}', 'ok')",
                )?;
                for i in 0..100_000_i64 {
                    stmt.execute(params![
                        i,
                        format!("action{}", i % 50),
                        format!("10.0.{}.{}", i % 250, i % 200)
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .unwrap();
        assert_eq!(s.audit_count().unwrap(), 100_000);

        let queries = [
            AuditQuery::recent(100),
            AuditQuery {
                since_ms: Some(99_000),
                ..AuditQuery::recent(100)
            },
            AuditQuery {
                action: Some("action7".into()),
                ..AuditQuery::recent(100)
            },
            AuditQuery {
                action: Some("action7".into()),
                since_ms: Some(50_000),
                ..AuditQuery::recent(100)
            },
            AuditQuery {
                target: Some("10.0.5.5".into()),
                ..AuditQuery::recent(100)
            },
            AuditQuery {
                actor: Some(AuditActor::Agent),
                ..AuditQuery::recent(100)
            },
        ];
        for q in &queries {
            let plan = s.audit_query_plan(q);
            assert!(
                plan.contains("USING INDEX") || plan.contains("USING COVERING INDEX"),
                "{q:?}: {plan}"
            );
            assert!(!plan.contains("TEMP B-TREE"), "{q:?}: {plan}");
            let started = Instant::now();
            let rows = s.audit_query(q).unwrap();
            let took = started.elapsed();
            assert!(!rows.is_empty(), "{q:?}");
            assert!(took.as_millis() < 1000, "{q:?} took {took:?}");
        }
    }
}
