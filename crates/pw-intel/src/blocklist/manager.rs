// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Per-list state, the refresh step and the "keep the last good list" rule.

use std::collections::BTreeMap;
use std::sync::Arc;

use pw_core::{Cidr, CidrSet};
use serde::{Deserialize, Serialize};

use super::parse::{build_list, exclude_protected, ParseLimits, ParseReport};
use super::scheduler::{clamp_interval, is_due, next_attempt, ScheduleState};
use super::source::{download, BlocklistError, ListSource};
use super::verify::{Verifier, VerifyError};
use crate::{Clock, Fetcher, UnixSecs};

/// User-facing settings of one list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListConfig {
    pub enabled: bool,
    pub refresh_interval_secs: u64,
}

/// What the UI shows for one list: enable toggle, refresh interval and last-update status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListStatus {
    pub id: String,
    pub enabled: bool,
    pub refresh_interval_secs: u64,
    pub last_attempt: Option<UnixSecs>,
    pub last_success: Option<UnixSecs>,
    /// Message of the most recent failure; cleared by the next success. The previous good list stays in use.
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    /// Blocks in the current list after sanitising and aggregation (before the protected set).
    pub entries: usize,
    pub next_attempt: Option<UnixSecs>,
    /// `Some(reason)` when the list cannot be enabled at all (the XeroHost list without a pinned key).
    pub unavailable: Option<String>,
    pub report: Option<ParseReport>,
}

/// A successfully downloaded, verified and sanitised list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSnapshot {
    pub id: String,
    pub fetched_at: UnixSecs,
    /// Aggregated public blocks before the protected set is subtracted.
    pub public_blocks: Vec<Cidr>,
    /// `public_blocks` minus the protected set at refresh time.
    pub effective_blocks: Vec<Cidr>,
    pub report: ParseReport,
}

impl ListSnapshot {
    /// The blocks to apply for the *current* protected set (recomputed, so a newly trusted address is carved out
    /// without downloading again).
    pub fn effective_for(&self, protected: &CidrSet) -> Vec<Cidr> {
        exclude_protected(&self.public_blocks, protected)
    }
}

struct Entry {
    source: ListSource,
    config: ListConfig,
    sched: ScheduleState,
    last_error: Option<String>,
    snapshot: Option<Arc<ListSnapshot>>,
}

/// Owns every list's state. All I/O goes through the `Fetcher` passed to [`BlocklistManager::refresh`].
pub struct BlocklistManager {
    entries: BTreeMap<String, Entry>,
    verifier: Verifier,
    limits: ParseLimits,
    clock: Arc<dyn Clock>,
}

impl BlocklistManager {
    pub fn new(sources: Vec<ListSource>, verifier: Verifier, clock: Arc<dyn Clock>) -> Self {
        let entries = sources
            .into_iter()
            .map(|source| {
                let config = ListConfig {
                    enabled: false,
                    refresh_interval_secs: clamp_interval(source.default_refresh_secs),
                };
                (
                    source.id.to_owned(),
                    Entry {
                        source,
                        config,
                        sched: ScheduleState::default(),
                        last_error: None,
                        snapshot: None,
                    },
                )
            })
            .collect();
        Self {
            entries,
            verifier,
            limits: ParseLimits::default(),
            clock,
        }
    }

    /// Production setup: the built-in sources and the pinned key.
    pub fn with_builtin_sources(clock: Arc<dyn Clock>) -> Self {
        Self::new(super::source::builtin_sources(), Verifier::pinned(), clock)
    }

    /// Override the parse limits (tests).
    #[must_use]
    pub fn with_limits(mut self, limits: ParseLimits) -> Self {
        self.limits = limits;
        self
    }

    fn entry(&self, id: &str) -> Result<&Entry, BlocklistError> {
        self.entries
            .get(id)
            .ok_or_else(|| BlocklistError::UnknownList(id.to_owned()))
    }

    fn entry_mut(&mut self, id: &str) -> Result<&mut Entry, BlocklistError> {
        self.entries
            .get_mut(id)
            .ok_or_else(|| BlocklistError::UnknownList(id.to_owned()))
    }

    fn unavailable(&self, entry: &Entry) -> Option<String> {
        if entry.source.is_signed() {
            self.verifier
                .check_ready()
                .err()
                .map(|e: VerifyError| e.to_string())
        } else {
            None
        }
    }

    pub fn ids(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn source(&self, id: &str) -> Option<&ListSource> {
        self.entries.get(id).map(|e| &e.source)
    }

    /// Enable or disable a list. Enabling a signed list without a usable pinned key fails (typed error) and leaves it
    /// disabled: the XeroHost list fails closed.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), BlocklistError> {
        if enabled {
            let entry = self.entry(id)?;
            if entry.source.is_signed() {
                self.verifier.check_ready()?;
            }
        }
        self.entry_mut(id)?.config.enabled = enabled;
        Ok(())
    }

    pub fn set_refresh_interval(&mut self, id: &str, secs: u64) -> Result<(), BlocklistError> {
        self.entry_mut(id)?.config.refresh_interval_secs = clamp_interval(secs);
        Ok(())
    }

    /// Restore persisted state at startup. A signed list that is saved as enabled but has no usable key stays
    /// disabled (and `status().unavailable` says why).
    pub fn restore(
        &mut self,
        id: &str,
        config: ListConfig,
        sched: ScheduleState,
        snapshot: Option<ListSnapshot>,
    ) -> Result<(), BlocklistError> {
        let blocked = {
            let entry = self.entry(id)?;
            entry.source.is_signed() && self.verifier.check_ready().is_err()
        };
        let entry = self.entry_mut(id)?;
        entry.config = ListConfig {
            enabled: config.enabled && !blocked,
            refresh_interval_secs: clamp_interval(config.refresh_interval_secs),
        };
        entry.sched = sched;
        entry.snapshot = snapshot.map(Arc::new);
        Ok(())
    }

    pub fn status(&self, id: &str) -> Option<ListStatus> {
        let entry = self.entries.get(id)?;
        let report = entry.snapshot.as_ref().map(|s| s.report.clone());
        Some(ListStatus {
            id: id.to_owned(),
            enabled: entry.config.enabled,
            refresh_interval_secs: entry.config.refresh_interval_secs,
            last_attempt: entry.sched.last_attempt,
            last_success: entry.sched.last_success,
            last_error: entry.last_error.clone(),
            consecutive_failures: entry.sched.consecutive_failures,
            entries: entry.snapshot.as_ref().map_or(0, |s| s.public_blocks.len()),
            next_attempt: entry
                .config
                .enabled
                .then(|| next_attempt(&entry.sched, entry.config.refresh_interval_secs)),
            unavailable: self.unavailable(entry),
            report,
        })
    }

    pub fn statuses(&self) -> Vec<ListStatus> {
        self.entries
            .keys()
            .filter_map(|id| self.status(id))
            .collect()
    }

    pub fn snapshot(&self, id: &str) -> Option<Arc<ListSnapshot>> {
        self.entries.get(id)?.snapshot.clone()
    }

    /// Ids of enabled lists whose refresh is due now.
    pub fn due(&self) -> Vec<String> {
        let now = self.clock.now();
        self.entries
            .iter()
            .filter(|(_, e)| {
                e.config.enabled && is_due(&e.sched, e.config.refresh_interval_secs, now)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The blocks of every **enabled** list with a snapshot, minus the *current* protected set.
    pub fn active_blocks(&self, protected: &CidrSet) -> Vec<(String, Vec<Cidr>)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.config.enabled)
            .filter_map(|(id, e)| Some((id.clone(), e.snapshot.as_ref()?.effective_for(protected))))
            .collect()
    }

    /// Download, verify, parse and store one list. On any failure the previous good snapshot is kept, the failure
    /// is recorded (with backoff) and the error is returned.
    pub async fn refresh<F: Fetcher>(
        &mut self,
        id: &str,
        fetcher: &F,
        protected: &CidrSet,
    ) -> Result<Arc<ListSnapshot>, BlocklistError> {
        let now = self.clock.now();
        let (source, enabled) = {
            let entry = self.entry(id)?;
            (entry.source.clone(), entry.config.enabled)
        };
        if !enabled {
            return Err(BlocklistError::Disabled);
        }
        let limits = ParseLimits {
            // Only the signed list may legitimately be empty; an empty public list is far more likely an error.
            allow_empty: source.is_signed(),
            ..self.limits
        };
        let result = async {
            let data = download(fetcher, &source, &self.verifier, limits.max_bytes).await?;
            let built = build_list(&data, &limits, protected)?;
            Ok::<_, BlocklistError>(built)
        }
        .await;

        let entry = self.entry_mut(id)?;
        entry.sched.last_attempt = Some(now);
        match result {
            Ok(built) => {
                let snapshot = Arc::new(ListSnapshot {
                    id: id.to_owned(),
                    fetched_at: now,
                    public_blocks: built.public_blocks,
                    effective_blocks: built.effective_blocks,
                    report: built.report,
                });
                entry.snapshot = Some(Arc::clone(&snapshot));
                entry.sched.last_success = Some(now);
                entry.sched.consecutive_failures = 0;
                entry.last_error = None;
                tracing::info!(
                    list = id,
                    entries = snapshot.public_blocks.len(),
                    "blocklist refreshed"
                );
                Ok(snapshot)
            }
            Err(error) => {
                entry.sched.consecutive_failures =
                    entry.sched.consecutive_failures.saturating_add(1);
                entry.last_error = Some(error.to_string());
                tracing::warn!(
                    list = id,
                    %error,
                    kept_previous = entry.snapshot.is_some(),
                    "blocklist refresh failed; keeping the last good list"
                );
                Err(error)
            }
        }
    }

    /// Refresh every enabled list that is due, one after another.
    pub async fn refresh_due<F: Fetcher>(
        &mut self,
        fetcher: &F,
        protected: &CidrSet,
    ) -> Vec<(String, Result<Arc<ListSnapshot>, BlocklistError>)> {
        let mut results = Vec::new();
        for id in self.due() {
            let result = self.refresh(&id, fetcher, protected).await;
            results.push((id, result));
        }
        results
    }
}
