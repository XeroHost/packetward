// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The alert inbox: incidents, one row per incident id, updated in place as it escalates and ends.
//! Field names follow `pw_proto::AlertView`; the engine maps between the two.

use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

use crate::error::{to_i64, to_u64, Result, StoreError};
use crate::store::{clip, Store};

const MAX_TEXT_BYTES: usize = 256;
const MAX_METRICS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            other => return Err(StoreError::InvalidData(format!("alert severity {other:?}"))),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertPhase {
    Started,
    Escalated,
    /// Over; the only phase retention may prune and `alerts_clear_ended` removes.
    Ended,
}

impl AlertPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Escalated => "escalated",
            Self::Ended => "ended",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "started" => Self::Started,
            "escalated" => Self::Escalated,
            "ended" => Self::Ended,
            other => return Err(StoreError::InvalidData(format!("alert phase {other:?}"))),
        })
    }
}

/// A named number of an alert (the unit is part of the key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertMetricRecord {
    pub key: String,
    pub value: u64,
}

/// One incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    /// Chosen by the caller; every update of an incident uses the same id. See
    /// [`Store::alerts_next_id`] for a restart-safe source.
    pub id: u64,
    /// Detector kind as a stable string (`syn_flood`, `port_scan`, ...); not validated here.
    pub kind: String,
    pub severity: AlertSeverity,
    pub source: Option<String>,
    pub summary_key: String,
    pub metrics: Vec<AlertMetricRecord>,
    pub window_secs: u32,
    pub first_seen_unix_ms: i64,
    pub last_seen_unix_ms: i64,
    pub protected: bool,
    pub peak_severity: AlertSeverity,
    pub phase: AlertPhase,
}

const COLUMNS: &str = "id, kind, severity, source, summary_key, metrics, window_secs, \
    first_seen_ms, last_seen_ms, protected, peak_severity, phase";

fn row_to_alert(row: &Row<'_>) -> Result<AlertRecord> {
    let metrics: String = row.get(5)?;
    let severity: String = row.get(2)?;
    let peak: String = row.get(10)?;
    let phase: String = row.get(11)?;
    Ok(AlertRecord {
        id: to_u64(row.get(0)?, "alert id")?,
        kind: row.get(1)?,
        severity: AlertSeverity::parse(&severity)?,
        source: row.get(3)?,
        summary_key: row.get(4)?,
        metrics: serde_json::from_str(&metrics)?,
        window_secs: u32::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
        first_seen_unix_ms: row.get(7)?,
        last_seen_unix_ms: row.get(8)?,
        protected: row.get::<_, i64>(9)? != 0,
        peak_severity: AlertSeverity::parse(&peak)?,
        phase: AlertPhase::parse(&phase)?,
    })
}

impl Store {
    /// Inserts or updates the incident `alert.id` (idempotent), then enforces
    /// `Limits::alerts_keep` by pruning the oldest *ended* incidents (by `last_seen`). Incidents
    /// that are still running are never pruned, so the table can exceed the bound while many are
    /// ongoing. `peak_severity` is kept at the highest of the stored and the new value.
    pub fn alert_upsert(&self, alert: &AlertRecord) -> Result<()> {
        let id = to_i64(alert.id, "alert id")?;
        let metrics: Vec<&AlertMetricRecord> = alert.metrics.iter().take(MAX_METRICS).collect();
        let metrics = serde_json::to_string(&metrics)?;
        let keep = i64::try_from(self.limits.alerts_keep).unwrap_or(i64::MAX);
        self.with(|conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO alerts(id, kind, severity, source, summary_key, metrics, window_secs, \
                   first_seen_ms, last_seen_ms, protected, peak_severity, phase) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(id) DO UPDATE SET \
                   kind = excluded.kind, severity = excluded.severity, source = excluded.source, \
                   summary_key = excluded.summary_key, metrics = excluded.metrics, \
                   window_secs = excluded.window_secs, \
                   first_seen_ms = min(alerts.first_seen_ms, excluded.first_seen_ms), \
                   last_seen_ms = excluded.last_seen_ms, protected = excluded.protected, \
                   peak_severity = CASE \
                     WHEN excluded.peak_severity IN ('critical') OR alerts.peak_severity = 'critical' THEN 'critical' \
                     WHEN excluded.peak_severity = 'high' OR alerts.peak_severity = 'high' THEN 'high' \
                     WHEN excluded.peak_severity = 'medium' OR alerts.peak_severity = 'medium' THEN 'medium' \
                     ELSE 'low' END, \
                   phase = excluded.phase",
                params![
                    id,
                    clip(&alert.kind, MAX_TEXT_BYTES),
                    alert.severity.as_str(),
                    alert.source.as_deref().map(|s| clip(s, MAX_TEXT_BYTES)),
                    clip(&alert.summary_key, MAX_TEXT_BYTES),
                    metrics,
                    i64::from(alert.window_secs),
                    alert.first_seen_unix_ms,
                    alert.last_seen_unix_ms,
                    i64::from(alert.protected),
                    alert.peak_severity.as_str(),
                    alert.phase.as_str(),
                ],
            )?;
            // Over the bound: drop the oldest ended incidents until it fits (or none are left).
            tx.execute(
                "DELETE FROM alerts WHERE id IN ( \
                   SELECT id FROM alerts WHERE phase = 'ended' \
                   ORDER BY last_seen_ms ASC, id ASC \
                   LIMIT max(0, (SELECT count(*) FROM alerts) - ?1))",
                [keep],
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn alert_get(&self, id: u64) -> Result<Option<AlertRecord>> {
        let id = to_i64(id, "alert id")?;
        self.with(|conn| {
            let mut stmt =
                conn.prepare_cached(&format!("SELECT {COLUMNS} FROM alerts WHERE id = ?1"))?;
            let row = stmt
                .query_row([id], |row| Ok(row_to_alert(row)))
                .optional()?;
            row.transpose()
        })
    }

    /// The most recent incidents, newest first (`last_seen`, then `id`).
    pub fn alerts_recent(&self, limit: usize) -> Result<Vec<AlertRecord>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "SELECT {COLUMNS} FROM alerts ORDER BY last_seen_ms DESC, id DESC LIMIT ?1"
            ))?;
            let mut rows = stmt.query([limit])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                match row_to_alert(row) {
                    Ok(alert) => out.push(alert),
                    Err(error) => tracing::warn!(%error, "skipping unreadable alert row"),
                }
            }
            Ok(out)
        })
    }

    /// Removes the incidents that ended; ongoing ones stay. Returns how many went.
    pub fn alerts_clear_ended(&self) -> Result<usize> {
        self.with(|conn| Ok(conn.execute("DELETE FROM alerts WHERE phase = 'ended'", [])?))
    }

    /// Marks every incident that is still running as ended (call at agent start: whatever was
    /// running when the agent stopped is over). Returns how many changed.
    pub fn alerts_end_ongoing(&self) -> Result<usize> {
        self.with(|conn| {
            Ok(conn.execute(
                "UPDATE alerts SET phase = 'ended' WHERE phase <> 'ended'",
                [],
            )?)
        })
    }

    /// One past the highest stored id (1 for an empty inbox). Ids can repeat only if the newest
    /// incident was pruned and the agent restarted before a newer one was stored.
    pub fn alerts_next_id(&self) -> Result<u64> {
        self.with(|conn| {
            let max: Option<i64> =
                conn.query_row("SELECT max(id) FROM alerts", [], |r| r.get(0))?;
            Ok(u64::try_from(max.unwrap_or(0))
                .unwrap_or(0)
                .saturating_add(1))
        })
    }

    pub fn alerts_count(&self) -> Result<u64> {
        self.with(|conn| {
            let n: i64 = conn.query_row("SELECT count(*) FROM alerts", [], |r| r.get(0))?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// The highest stored id in `lo..hi` (`hi` exclusive), `None` when there is none. Lets the
    /// caller keep separate id ranges (detector incidents, logon notices) restart-safe.
    pub fn alerts_max_id_in(&self, lo: u64, hi: u64) -> Result<Option<u64>> {
        let lo = to_i64(lo, "alert id")?;
        let hi = i64::try_from(hi).unwrap_or(i64::MAX);
        self.with(|conn| {
            let max: Option<i64> = conn.query_row(
                "SELECT max(id) FROM alerts WHERE id >= ?1 AND id < ?2",
                [lo, hi],
                |r| r.get(0),
            )?;
            Ok(max.and_then(|v| u64::try_from(v).ok()))
        })
    }

    /// Retention: removes the *ended* incidents last seen before `older_than_ms` (when given), then
    /// the oldest ended ones until at most `keep` rows are left. Incidents that are still running
    /// are never removed, so the table can stay above `keep` while many are ongoing.
    pub fn alerts_prune(&self, older_than_ms: Option<i64>, keep: u64) -> Result<AlertsPruned> {
        let keep = i64::try_from(keep).unwrap_or(i64::MAX);
        self.with(|conn| {
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let by_age = match older_than_ms {
                Some(cutoff) => tx.execute(
                    "DELETE FROM alerts WHERE phase = 'ended' AND last_seen_ms < ?1",
                    [cutoff],
                )?,
                None => 0,
            };
            let by_rows = tx.execute(
                "DELETE FROM alerts WHERE id IN ( \
                   SELECT id FROM alerts WHERE phase = 'ended' \
                   ORDER BY last_seen_ms ASC, id ASC \
                   LIMIT max(0, (SELECT count(*) FROM alerts) - ?1))",
                [keep],
            )?;
            tx.commit()?;
            Ok(AlertsPruned { by_age, by_rows })
        })
    }
}

/// What [`Store::alerts_prune`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AlertsPruned {
    /// Ended incidents older than the age limit.
    pub by_age: usize,
    /// Further ended incidents removed to get under the row cap.
    pub by_rows: usize,
}

impl AlertsPruned {
    pub const fn total(self) -> usize {
        self.by_age + self.by_rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Limits;

    fn mem() -> Store {
        Store::open_in_memory().unwrap()
    }

    fn alert(id: u64, last_seen: i64, phase: AlertPhase) -> AlertRecord {
        AlertRecord {
            id,
            kind: "syn_flood".into(),
            severity: AlertSeverity::High,
            source: Some("203.0.113.5".into()),
            summary_key: "syn_flood".into(),
            metrics: vec![
                AlertMetricRecord {
                    key: "syn_pps".into(),
                    value: 120_000,
                },
                AlertMetricRecord {
                    key: "big".into(),
                    value: u64::MAX,
                },
            ],
            window_secs: 10,
            first_seen_unix_ms: 1_000,
            last_seen_unix_ms: last_seen,
            protected: false,
            peak_severity: AlertSeverity::High,
            phase,
        }
    }

    #[test]
    fn roundtrip_including_large_metrics() {
        let s = mem();
        let a = alert(7, 2_000, AlertPhase::Started);
        s.alert_upsert(&a).unwrap();
        assert_eq!(s.alert_get(7).unwrap(), Some(a.clone()));
        assert_eq!(s.alerts_recent(10).unwrap(), vec![a]);
        assert_eq!(s.alert_get(8).unwrap(), None);
    }

    #[test]
    fn upsert_updates_in_place_and_is_idempotent() {
        let s = mem();
        let mut a = alert(1, 2_000, AlertPhase::Started);
        s.alert_upsert(&a).unwrap();
        s.alert_upsert(&a).unwrap();
        assert_eq!(s.alerts_count().unwrap(), 1);

        a.severity = AlertSeverity::Critical;
        a.peak_severity = AlertSeverity::Critical;
        a.phase = AlertPhase::Escalated;
        a.last_seen_unix_ms = 3_000;
        a.protected = true;
        s.alert_upsert(&a).unwrap();
        // Severity falls back, but the peak stays at its highest.
        a.severity = AlertSeverity::Low;
        a.peak_severity = AlertSeverity::Low;
        a.phase = AlertPhase::Ended;
        a.last_seen_unix_ms = 4_000;
        s.alert_upsert(&a).unwrap();

        let got = s.alert_get(1).unwrap().unwrap();
        assert_eq!(s.alerts_count().unwrap(), 1);
        assert_eq!(got.severity, AlertSeverity::Low);
        assert_eq!(got.peak_severity, AlertSeverity::Critical);
        assert_eq!(got.phase, AlertPhase::Ended);
        assert_eq!(got.last_seen_unix_ms, 4_000);
        assert!(got.protected);
        assert_eq!(got.first_seen_unix_ms, 1_000);
    }

    #[test]
    fn recent_is_newest_first_with_limit() {
        let s = mem();
        s.alert_upsert(&alert(1, 100, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(2, 300, AlertPhase::Started)).unwrap();
        s.alert_upsert(&alert(3, 300, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(4, 200, AlertPhase::Ended)).unwrap();
        let ids: Vec<u64> = s.alerts_recent(10).unwrap().iter().map(|a| a.id).collect();
        assert_eq!(ids, [3, 2, 4, 1]);
        assert_eq!(s.alerts_recent(2).unwrap().len(), 2);
        assert!(s.alerts_recent(0).unwrap().is_empty());
    }

    #[test]
    fn clear_ended_keeps_ongoing() {
        let s = mem();
        s.alert_upsert(&alert(1, 100, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(2, 100, AlertPhase::Started)).unwrap();
        s.alert_upsert(&alert(3, 100, AlertPhase::Escalated))
            .unwrap();
        s.alert_upsert(&alert(4, 100, AlertPhase::Ended)).unwrap();
        assert_eq!(s.alerts_clear_ended().unwrap(), 2);
        let ids: Vec<u64> = s.alerts_recent(10).unwrap().iter().map(|a| a.id).collect();
        assert_eq!(ids, [3, 2]);
        assert_eq!(s.alerts_clear_ended().unwrap(), 0);
    }

    #[test]
    fn end_ongoing_on_restart() {
        let s = mem();
        s.alert_upsert(&alert(1, 100, AlertPhase::Started)).unwrap();
        s.alert_upsert(&alert(2, 100, AlertPhase::Escalated))
            .unwrap();
        s.alert_upsert(&alert(3, 100, AlertPhase::Ended)).unwrap();
        assert_eq!(s.alerts_end_ongoing().unwrap(), 2);
        assert!(s
            .alerts_recent(10)
            .unwrap()
            .iter()
            .all(|a| a.phase == AlertPhase::Ended));
    }

    #[test]
    fn retention_prunes_oldest_ended_only() {
        let limits = Limits {
            alerts_keep: 5,
            ..Limits::default()
        };
        let s = Store::open_in_memory_with(limits).unwrap();
        // Two ongoing incidents that are the oldest of all must survive.
        s.alert_upsert(&alert(1, 1, AlertPhase::Started)).unwrap();
        s.alert_upsert(&alert(2, 2, AlertPhase::Escalated)).unwrap();
        for i in 3..=40u64 {
            s.alert_upsert(&alert(i, i as i64, AlertPhase::Ended))
                .unwrap();
        }
        assert_eq!(s.alerts_count().unwrap(), 5);
        assert!(s.alert_get(1).unwrap().is_some());
        assert!(s.alert_get(2).unwrap().is_some());
        // The three newest ended ones are what is left besides them.
        let ids: Vec<u64> = s.alerts_recent(10).unwrap().iter().map(|a| a.id).collect();
        assert_eq!(ids, [40, 39, 38, 2, 1]);
    }

    #[test]
    fn retention_never_prunes_ongoing_even_over_the_bound() {
        let limits = Limits {
            alerts_keep: 3,
            ..Limits::default()
        };
        let s = Store::open_in_memory_with(limits).unwrap();
        for i in 1..=10u64 {
            s.alert_upsert(&alert(i, i as i64, AlertPhase::Started))
                .unwrap();
        }
        assert_eq!(s.alerts_count().unwrap(), 10);
    }

    #[test]
    fn default_keep_is_5000() {
        assert_eq!(Limits::default().alerts_keep, 5000);
    }

    #[test]
    fn next_id_follows_the_highest_stored() {
        let s = mem();
        assert_eq!(s.alerts_next_id().unwrap(), 1);
        s.alert_upsert(&alert(41, 1, AlertPhase::Ended)).unwrap();
        assert_eq!(s.alerts_next_id().unwrap(), 42);
    }

    #[test]
    fn hostile_text_and_big_ids() {
        let s = mem();
        let mut a = alert(1, 1, AlertPhase::Started);
        a.source = Some("1.2.3.4'; DROP TABLE alerts;--".into());
        a.summary_key = "a\0b".into();
        a.kind = "é".repeat(10_000);
        s.alert_upsert(&a).unwrap();
        let got = s.alert_get(1).unwrap().unwrap();
        assert_eq!(got.source, a.source);
        assert_eq!(got.summary_key, "a\0b");
        assert!(got.kind.len() <= MAX_TEXT_BYTES);
        // An id that does not fit SQLite's integer is refused, not wrapped.
        a.id = u64::MAX;
        assert!(matches!(
            s.alert_upsert(&a),
            Err(StoreError::InvalidInput(_))
        ));
        assert_eq!(s.alerts_count().unwrap(), 1);
    }

    #[test]
    fn max_id_in_a_range() {
        let s = mem();
        assert_eq!(s.alerts_max_id_in(1, 100).unwrap(), None);
        s.alert_upsert(&alert(5, 1, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(50, 1, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(100, 1, AlertPhase::Ended)).unwrap();
        assert_eq!(s.alerts_max_id_in(1, 100).unwrap(), Some(50));
        assert_eq!(s.alerts_max_id_in(100, u64::MAX).unwrap(), Some(100));
        assert_eq!(s.alerts_max_id_in(6, 50).unwrap(), None);
    }

    #[test]
    fn prune_by_age_then_by_rows_never_touches_ongoing() {
        let s = mem();
        s.alert_upsert(&alert(1, 10, AlertPhase::Started)).unwrap(); // old but running
        s.alert_upsert(&alert(2, 20, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(3, 30, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(4, 100, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(5, 110, AlertPhase::Ended)).unwrap();
        s.alert_upsert(&alert(6, 120, AlertPhase::Ended)).unwrap();
        let pruned = s.alerts_prune(Some(50), 3).unwrap();
        assert_eq!(
            pruned,
            AlertsPruned {
                by_age: 2,
                by_rows: 1
            }
        );
        assert_eq!(pruned.total(), 3);
        let ids: Vec<u64> = s.alerts_recent(10).unwrap().iter().map(|a| a.id).collect();
        assert_eq!(
            ids,
            [6, 5, 1],
            "the running incident stays even over the cap"
        );
        assert_eq!(s.alerts_prune(None, 100).unwrap(), AlertsPruned::default());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw.db");
        let a = alert(9, 5, AlertPhase::Started);
        {
            let s = Store::open(&path).unwrap().store;
            s.alert_upsert(&a).unwrap();
        }
        let s = Store::open(&path).unwrap().store;
        assert_eq!(s.alerts_recent(5).unwrap(), vec![a]);
    }
}
