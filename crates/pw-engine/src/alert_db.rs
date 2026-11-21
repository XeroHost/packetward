// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The alert inbox in the SQLite store (`packetward.db`), instead of `alerts.jsonl`. Enabled by the
//! `store` feature. Every failure here is logged and reported to the caller as "not written", so the
//! [`crate::detect::AlertStore`] can fall back to the JSON-lines file: a broken database must never
//! lose alerts or stop the detectors.
//!
//! An `alerts.jsonl` left by an older agent is imported once and renamed `alerts.jsonl.imported`.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use pw_proto::{AlertKindView, AlertMetric, AlertPhaseView, AlertSeverity, AlertView};
use pw_store::{AlertMetricRecord, AlertPhase, AlertRecord, Store};

use crate::detect::{merge_incident, AlertRetention, IdMarks, LOGON_ID_BASE};

const MARKS_KEY: &str = "alerts.id_marks";
const MS_PER_DAY: i64 = 24 * 3_600 * 1_000;

pub(crate) struct AlertDb {
    store: Arc<Store>,
    retention: AlertRetention,
}

fn severity_to_store(severity: AlertSeverity) -> pw_store::AlertSeverity {
    match severity {
        AlertSeverity::Low => pw_store::AlertSeverity::Low,
        AlertSeverity::Medium => pw_store::AlertSeverity::Medium,
        AlertSeverity::High => pw_store::AlertSeverity::High,
        AlertSeverity::Critical => pw_store::AlertSeverity::Critical,
    }
}

fn severity_from_store(severity: pw_store::AlertSeverity) -> AlertSeverity {
    match severity {
        pw_store::AlertSeverity::Low => AlertSeverity::Low,
        pw_store::AlertSeverity::Medium => AlertSeverity::Medium,
        pw_store::AlertSeverity::High => AlertSeverity::High,
        pw_store::AlertSeverity::Critical => AlertSeverity::Critical,
    }
}

fn phase_to_store(phase: AlertPhaseView) -> AlertPhase {
    match phase {
        AlertPhaseView::Started => AlertPhase::Started,
        AlertPhaseView::Escalated => AlertPhase::Escalated,
        AlertPhaseView::Ended => AlertPhase::Ended,
    }
}

fn phase_from_store(phase: AlertPhase) -> AlertPhaseView {
    match phase {
        AlertPhase::Started => AlertPhaseView::Started,
        AlertPhase::Escalated => AlertPhaseView::Escalated,
        AlertPhase::Ended => AlertPhaseView::Ended,
    }
}

/// The detector kind as the stable snake_case string the wire format uses.
fn kind_to_store(kind: AlertKindView) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn kind_from_store(text: &str) -> Option<AlertKindView> {
    serde_json::from_value(serde_json::Value::String(text.to_owned())).ok()
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn record_of(view: &AlertView) -> AlertRecord {
    AlertRecord {
        id: view.id,
        kind: kind_to_store(view.kind),
        severity: severity_to_store(view.severity),
        source: view.source.clone(),
        summary_key: view.summary_key.clone(),
        metrics: view
            .metrics
            .iter()
            .map(|m| AlertMetricRecord {
                key: m.key.clone(),
                value: m.value,
            })
            .collect(),
        window_secs: view.window_secs,
        first_seen_unix_ms: to_i64(view.first_seen_unix_ms),
        last_seen_unix_ms: to_i64(view.last_seen_unix_ms),
        protected: view.protected,
        peak_severity: severity_to_store(view.peak_severity),
        phase: phase_to_store(view.phase),
    }
}

/// `None` for a row whose kind this build does not know (written by a newer agent).
fn view_of(record: AlertRecord) -> Option<AlertView> {
    Some(AlertView {
        id: record.id,
        phase: phase_from_store(record.phase),
        kind: kind_from_store(&record.kind)?,
        severity: severity_from_store(record.severity),
        source: record.source,
        summary_key: record.summary_key,
        metrics: record
            .metrics
            .into_iter()
            .map(|m| AlertMetric {
                key: m.key,
                value: m.value,
            })
            .collect(),
        window_secs: record.window_secs,
        first_seen_unix_ms: to_u64(record.first_seen_unix_ms),
        last_seen_unix_ms: to_u64(record.last_seen_unix_ms),
        protected: record.protected,
        peak_severity: severity_from_store(record.peak_severity),
    })
}

impl AlertDb {
    pub(crate) fn new(store: Arc<Store>, retention: AlertRetention) -> Self {
        Self { store, retention }
    }

    /// Inserts or updates one incident; false when the database refused (the caller falls back).
    pub(crate) fn upsert(&self, view: &AlertView) -> bool {
        match self.store.alert_upsert(&record_of(view)) {
            Ok(()) => true,
            Err(error) => {
                tracing::error!(%error, "could not store the alert; writing it to alerts.jsonl");
                false
            }
        }
    }

    /// The newest `limit` incidents, newest first.
    pub(crate) fn load_recent(&self, limit: usize) -> VecDeque<AlertView> {
        match self.store.alerts_recent(limit) {
            Ok(rows) => rows.into_iter().filter_map(view_of).collect(),
            Err(error) => {
                tracing::error!(%error, "could not read the stored alerts");
                VecDeque::new()
            }
        }
    }

    /// Whatever was running when the agent stopped is over now.
    pub(crate) fn end_ongoing(&self) {
        if let Err(error) = self.store.alerts_end_ongoing() {
            tracing::warn!(%error, "could not close the incidents left running");
        }
    }

    /// Removes every ended incident (the inbox "clear" action); `None` if the database refused.
    pub(crate) fn clear_ended(&self) -> Option<usize> {
        match self.store.alerts_clear_ended() {
            Ok(n) => Some(n),
            Err(error) => {
                tracing::error!(%error, "could not clear the stored alerts");
                None
            }
        }
    }

    /// Applies the retention (age, then row cap); returns how many incidents went.
    pub(crate) fn prune(&self, now_ms: u64) -> usize {
        let cutoff = (self.retention.days > 0)
            .then(|| to_i64(now_ms) - i64::from(self.retention.days) * MS_PER_DAY);
        match self
            .store
            .alerts_prune(cutoff, self.retention.max_rows.max(1))
        {
            Ok(pruned) => {
                if pruned.total() > 0 {
                    tracing::info!(
                        by_age = pruned.by_age,
                        by_rows = pruned.by_rows,
                        "pruned old alerts"
                    );
                }
                pruned.total()
            }
            Err(error) => {
                tracing::warn!(%error, "could not prune the stored alerts");
                0
            }
        }
    }

    /// The highest ids ever handed out: the saved marks (they survive pruning and clearing) or, when
    /// nothing was saved yet, what the table holds.
    pub(crate) fn marks(&self) -> IdMarks {
        let mut marks = self
            .store
            .kv_get::<IdMarks>(MARKS_KEY)
            .ok()
            .flatten()
            .unwrap_or_default();
        let detector = self.store.alerts_max_id_in(0, LOGON_ID_BASE);
        let logon = self.store.alerts_max_id_in(LOGON_ID_BASE, u64::MAX);
        if let Ok(Some(id)) = detector {
            marks.raise(id);
        }
        if let Ok(Some(id)) = logon {
            marks.raise(id);
        }
        marks
    }

    pub(crate) fn save_marks(&self, marks: &IdMarks) {
        let now = i64::try_from(crate::poller::unix_ms()).unwrap_or(i64::MAX);
        if let Err(error) = self.store.kv_set(MARKS_KEY, marks, now) {
            tracing::warn!(%error, "could not save the alert id marks");
        }
    }

    /// Imports an `alerts.jsonl` left by an older agent, once: the file is renamed afterwards.
    pub(crate) fn import_legacy(&self, path: &Path) {
        let Ok(text) = fs::read_to_string(path) else {
            return;
        };
        let mut merged: HashMap<u64, AlertView> = HashMap::new();
        let mut order: Vec<u64> = Vec::new();
        for line in text.lines() {
            let Ok(event) = serde_json::from_str::<AlertView>(line) else {
                continue;
            };
            let id = event.id;
            let next = merge_incident(merged.get(&id), event);
            if merged.insert(id, next).is_none() {
                order.push(id);
            }
        }
        let mut imported = 0usize;
        for id in order {
            if let Some(mut view) = merged.remove(&id) {
                view.phase = AlertPhaseView::Ended;
                if self.upsert(&view) {
                    imported += 1;
                }
            }
        }
        let mut renamed = path.as_os_str().to_owned();
        renamed.push(".imported");
        match fs::rename(path, &renamed) {
            Ok(()) => tracing::info!(imported, "imported alerts.jsonl into the database"),
            Err(error) => tracing::warn!(%error, "imported alerts.jsonl but could not rename it"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::AlertStore;

    fn view(id: u64, phase: AlertPhaseView, seen: u64) -> AlertView {
        AlertView {
            id,
            phase,
            kind: AlertKindView::PortScan,
            severity: AlertSeverity::High,
            source: Some("203.0.113.9".to_owned()),
            summary_key: "port_scan_vertical".to_owned(),
            metrics: vec![AlertMetric {
                key: "ports".to_owned(),
                value: 99,
            }],
            window_secs: 10,
            first_seen_unix_ms: seen,
            last_seen_unix_ms: seen,
            protected: false,
            peak_severity: AlertSeverity::High,
        }
    }

    /// The fixtures use timestamps near the epoch: nothing may be pruned by age on start.
    fn keep_all() -> AlertRetention {
        AlertRetention {
            days: 0,
            max_rows: 10_000,
        }
    }

    fn store() -> Arc<Store> {
        Arc::new(Store::open_in_memory().expect("in-memory store"))
    }

    #[test]
    fn a_view_survives_the_round_trip_through_the_database() {
        let db = AlertDb::new(store(), keep_all());
        let original = view(7, AlertPhaseView::Started, 1_000);
        assert!(db.upsert(&original));
        assert_eq!(db.load_recent(10), VecDeque::from([original]));
    }

    #[test]
    fn alerts_survive_a_restart_and_ids_keep_growing() {
        let shared = store();
        {
            let alerts = AlertStore::with_store(Arc::clone(&shared), None, keep_all());
            alerts.record(view(1, AlertPhaseView::Started, 1_000));
            alerts.record(view(2, AlertPhaseView::Started, 2_000));
        }
        let alerts = AlertStore::with_store(Arc::clone(&shared), None, keep_all());
        let list = alerts.list().alerts;
        assert_eq!(list.len(), 2);
        assert!(
            list.iter().all(|a| a.phase == AlertPhaseView::Ended),
            "what was running when the agent stopped is over"
        );
        assert_eq!(alerts.detector_id_offset(), 2, "the next incident is 3");
        assert_eq!(alerts.first_logon_seq(), 1);
    }

    #[test]
    fn ids_do_not_repeat_after_clearing_the_inbox() {
        let shared = store();
        {
            let alerts = AlertStore::with_store(Arc::clone(&shared), None, keep_all());
            alerts.record(view(5, AlertPhaseView::Started, 1_000));
            alerts.record(view(5, AlertPhaseView::Ended, 2_000));
            assert_eq!(alerts.clear_ended(), 1);
        }
        let alerts = AlertStore::with_store(shared, None, keep_all());
        assert!(alerts.list().alerts.is_empty());
        assert_eq!(
            alerts.detector_id_offset(),
            5,
            "the cleared id is not reused"
        );
    }

    #[test]
    fn retention_removes_old_ended_incidents_and_keeps_the_running_ones() {
        let day = 24 * 3_600 * 1_000;
        let now = 200 * day;
        let alerts = AlertStore::with_store(
            store(),
            None,
            AlertRetention {
                days: 30,
                max_rows: 100,
            },
        );
        alerts.record(view(1, AlertPhaseView::Ended, now - 60 * day));
        alerts.record(view(2, AlertPhaseView::Ended, now - 10 * day));
        alerts.record(view(3, AlertPhaseView::Started, now - 90 * day));
        assert_eq!(alerts.prune_at(now), 1, "only the old ended one goes");
        let ids: Vec<u64> = alerts.list().alerts.iter().map(|a| a.id).collect();
        assert!(ids.contains(&2) && ids.contains(&3) && !ids.contains(&1));
    }

    #[test]
    fn the_row_cap_removes_the_oldest_ended_incidents_first() {
        let alerts = AlertStore::with_store(
            store(),
            None,
            AlertRetention {
                days: 0,
                max_rows: 2,
            },
        );
        for id in 1..=4 {
            alerts.record(view(id, AlertPhaseView::Ended, id * 1_000));
        }
        alerts.prune_at(10_000);
        let mut ids: Vec<u64> = alerts.list().alerts.iter().map(|a| a.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![3, 4]);
    }

    #[test]
    fn a_legacy_jsonl_is_imported_once_and_renamed() {
        let dir = std::env::temp_dir().join(format!("pw-alert-import-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let log = dir.join("alerts.jsonl");
        let lines = [
            view(1, AlertPhaseView::Started, 1_000),
            view(1, AlertPhaseView::Ended, 2_000),
            view(2, AlertPhaseView::Started, 3_000),
        ]
        .iter()
        .map(|v| serde_json::to_string(v).expect("serialize"))
        .collect::<Vec<_>>()
        .join("\n");
        fs::write(&log, lines).expect("write legacy log");

        let shared = store();
        let alerts = AlertStore::with_store(Arc::clone(&shared), Some(log.clone()), keep_all());
        assert_eq!(alerts.list().alerts.len(), 2);
        assert!(!log.exists(), "the legacy file is renamed");
        assert!(dir.join("alerts.jsonl.imported").exists());
        // Opening again does not import anything twice.
        let again = AlertStore::with_store(shared, Some(log), keep_all());
        assert_eq!(again.list().alerts.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kind_from_a_newer_agent_is_skipped_not_fatal() {
        assert!(kind_from_store("something_new").is_none());
        assert_eq!(kind_from_store("port_scan"), Some(AlertKindView::PortScan));
    }
}
