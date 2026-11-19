// SPDX-License-Identifier: GPL-3.0-or-later
//! The defense state (blocks, Guardian policy, allowlist) and the audit log in the SQLite store
//! (`packetward.db`), instead of `defense.json` / `audit.jsonl`. Enabled by the `store` feature.
//!
//! A `defense.json` left by an older agent is imported once (and renamed `defense.json.imported`);
//! an old `audit.jsonl` stays on disk, untouched, and is not imported.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pw_store::{AuditActor, AuditQuery, AuditResult, NewAudit, Store};
use serde_json::{json, Value};

use crate::defense::{AuditEntry, JsonPersistence, PersistedState, Persistence};

const STATE_KEY: &str = "defense.state";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The store-backed [`Persistence`].
pub struct StorePersistence {
    store: Arc<Store>,
    /// Where an older agent kept `defense.json` (imported once).
    legacy_dir: Option<PathBuf>,
}

impl StorePersistence {
    pub fn new(store: Arc<Store>, legacy_dir: Option<PathBuf>) -> Self {
        Self { store, legacy_dir }
    }
}

fn actor_of(actor: &str) -> AuditActor {
    match actor {
        "agent" => AuditActor::Agent,
        "guardian" => AuditActor::Guardian,
        "rdp_shield" | "rdp" => AuditActor::RdpShield,
        "blocklist" => AuditActor::Blocklist,
        "pwctl" => AuditActor::Pwctl,
        _ => AuditActor::Ui,
    }
}

fn result_of(result: &str) -> AuditResult {
    match result {
        "ok" => AuditResult::Ok,
        "refused" => AuditResult::Refused,
        _ => AuditResult::Failed,
    }
}

impl Persistence for StorePersistence {
    fn load(&self) -> PersistedState {
        match self.store.kv_get::<PersistedState>(STATE_KEY) {
            Ok(Some(state)) => return state,
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(%err, "the stored defense state is unreadable; starting from the defaults");
                return PersistedState::default();
            }
        }
        // First start with the store: take over the state of an older agent.
        let Some(dir) = &self.legacy_dir else {
            return PersistedState::default();
        };
        let legacy = dir.join("defense.json");
        if !legacy.exists() {
            return PersistedState::default();
        }
        let state = JsonPersistence::new(dir.clone()).load();
        match self.store.kv_set(STATE_KEY, &state, now_ms()) {
            Ok(()) => {
                let _ = fs::rename(&legacy, dir.join("defense.json.imported"));
                tracing::info!("imported defense.json into the store");
            }
            Err(err) => tracing::warn!(%err, "could not import defense.json into the store"),
        }
        state
    }

    fn save(&self, state: &PersistedState) {
        if let Err(err) = self.store.kv_set(STATE_KEY, state, now_ms()) {
            tracing::error!(%err, "could not save the defense state");
        }
    }

    fn audit(&self, entry: &AuditEntry) {
        // The engine's actor and result are free text: keep them as they were in `detail`.
        let event = NewAudit::new(
            i64::try_from(entry.unix_ms).unwrap_or(i64::MAX),
            actor_of(&entry.actor),
            entry.action.clone(),
            entry.target.clone(),
            result_of(&entry.result),
        )
        .with_detail(json!({
            "actor": entry.actor,
            "detail": entry.detail,
            "result": entry.result,
        }));
        if let Err(err) = self.store.audit_append(&event) {
            tracing::warn!(%err, "could not append to the audit log");
        }
    }

    fn read_audit(&self, limit: usize) -> Vec<AuditEntry> {
        let rows = match self.store.audit_query(&AuditQuery::recent(limit)) {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(%err, "could not read the audit log");
                return Vec::new();
            }
        };
        let text = |detail: &Value, key: &str, fallback: &str| {
            detail
                .get(key)
                .and_then(Value::as_str)
                .map_or_else(|| fallback.to_owned(), str::to_owned)
        };
        // The store returns newest first; the trait wants oldest first.
        rows.into_iter()
            .rev()
            .map(|row| AuditEntry {
                unix_ms: u64::try_from(row.ts_ms).unwrap_or(0),
                actor: text(&row.detail, "actor", row.actor.as_str()),
                action: row.action,
                target: row.target,
                detail: text(&row.detail, "detail", ""),
                result: text(&row.detail, "result", row.result.as_str()),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persistence(legacy: Option<PathBuf>) -> StorePersistence {
        StorePersistence::new(Arc::new(Store::open_in_memory().unwrap()), legacy)
    }

    fn entry(actor: &str, action: &str, result: &str) -> AuditEntry {
        AuditEntry {
            unix_ms: 1_700_000_000_000,
            actor: actor.into(),
            action: action.into(),
            target: "203.0.113.5".into(),
            detail: "why".into(),
            result: result.into(),
        }
    }

    #[test]
    fn the_state_round_trips() {
        let p = persistence(None);
        assert!(p.load().blocks.is_empty());
        let mut state = PersistedState::default();
        state.allowlist.allowlist.push("203.0.113.0/24".into());
        p.save(&state);
        assert_eq!(
            p.load().allowlist.allowlist,
            vec!["203.0.113.0/24".to_owned()]
        );
    }

    #[test]
    fn the_audit_keeps_free_text_actors_and_comes_back_oldest_first() {
        let p = persistence(None);
        p.audit(&entry("operator", "block", "ok"));
        let mut later = entry("guardian", "block", "refused");
        later.unix_ms += 1000;
        p.audit(&later);
        let rows = p.read_audit(10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].actor, "operator");
        assert_eq!(rows[0].detail, "why");
        assert_eq!(rows[1].result, "refused");
        assert_eq!(p.read_audit(1)[0].actor, "guardian", "the newest is kept");
    }

    #[test]
    fn an_older_defense_json_is_imported_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = PersistedState::default();
        state.allowlist.allowlist.push("198.51.100.0/24".into());
        JsonPersistence::new(dir.path().to_path_buf()).save(&state);
        let p = persistence(Some(dir.path().to_path_buf()));
        assert_eq!(
            p.load().allowlist.allowlist,
            vec!["198.51.100.0/24".to_owned()]
        );
        assert!(!dir.path().join("defense.json").exists());
        assert!(dir.path().join("defense.json.imported").exists());
        // The second load comes from the store.
        assert_eq!(
            p.load().allowlist.allowlist,
            vec!["198.51.100.0/24".to_owned()]
        );
    }
}
