// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Firewall manager and Guardian (M6, M7): the persisted set of blocks, the protected set, the
//! reconcile loop that applies them to Windows Firewall, and the Guardian that turns alerts into
//! blocks (or, in Monitor mode, into a report of what it would have blocked).
//!
//! Safety first: a protected address (loopback, the default gateway, DNS servers, addresses with a
//! successful RDP logon, the allowlist, management ranges) is never blocked, whoever asks; every
//! automatic block has a TTL, is audited and is reversible with `firewall.unblock_all`; a circuit
//! breaker limits how many automatic blocks an hour can contain; a fresh install is in Monitor mode.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use pw_core::{Cidr, CidrSet};
use pw_firewall::addr::{cidr_span, format_cidr};
use pw_firewall::guard::{is_too_broad, ProtectedSpans};
use pw_firewall::{
    BatchId, BlockOptions, Confirmation, DesiredBlock, Firewall, FirewallError, Protocol, Rule,
    RuleFilter, RuleOptions,
};
use pw_netstat::NetworkContext;
use pw_proto::{
    AlertPhaseView, AlertSeverity, AlertView, AllowlistConfig, BlockList, BlockRefusal,
    BlockRequest, BlockResult, BlockSource, BlockView, ErrorCode, ErrorPayload, FirewallRuleAction,
    FirewallRuleEdit, FirewallRuleView, FirewallRules, FirewallRulesRequest, GuardianDecision,
    GuardianMode, GuardianPolicy, GuardianStatus, ProtectedEntry, PurgeRequest, PurgeResult,
    RuleAction, RuleDirection, SetGuardianPolicy,
};
use serde::{Deserialize, Serialize};

use crate::trust::TrustState;

/// Rules sent to the UI at most (a Windows machine has hundreds; the list is filtered first).
pub const MAX_RULES_SHOWN: usize = 2000;
const MAX_DECISIONS: usize = 300;
const MAX_BLOCKS: usize = 20_000;
const MAX_TARGETS_PER_REQUEST: usize = 5_000;
const MIN_TTL_SECS: u64 = 60;
const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_LADDER_STEPS: usize = 6;
const HOUR_SECS: u64 = 3600;
const DAY_SECS: u64 = 24 * 3600;
/// How long an address keeps its escalation level after its last block.
const ESCALATION_MEMORY_SECS: u64 = 30 * DAY_SECS;
const AUDIT_MAX_BYTES: u64 = 20 * 1024 * 1024;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn internal(message: impl ToString) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::Internal, message.to_string())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn firewall_error(err: FirewallError) -> ErrorPayload {
    match err {
        FirewallError::Backend { .. } => internal(err),
        other => bad_request(other.to_string()),
    }
}

// ---- persistence ----------------------------------------------------------------------------------

/// A block as it is kept on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBlock {
    pub cidr: String,
    pub manual: bool,
    pub reason: String,
    pub created_secs: u64,
    pub expires_secs: Option<u64>,
    pub alert_id: Option<u64>,
    pub escalation: u8,
}

/// Everything the defense layer remembers across restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedState {
    pub blocks: Vec<StoredBlock>,
    pub policy: Option<GuardianPolicy>,
    pub allowlist: AllowlistConfig,
    /// Address → (escalation level reached, unix seconds of its last block).
    pub escalation: BTreeMap<String, (u8, u64)>,
}

/// One audited action (appended to `audit.jsonl`; never edited).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub unix_ms: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub result: String,
}

pub trait Persistence: Send + Sync {
    fn load(&self) -> PersistedState;
    fn save(&self, state: &PersistedState);
    fn audit(&self, entry: &AuditEntry);
    /// The newest audit entries (oldest first), at most `limit`.
    fn read_audit(&self, limit: usize) -> Vec<AuditEntry>;
}

/// Keeps nothing (tests, tools).
#[derive(Default)]
pub struct MemoryPersistence {
    pub audit_log: Mutex<Vec<AuditEntry>>,
}

impl Persistence for MemoryPersistence {
    fn load(&self) -> PersistedState {
        PersistedState::default()
    }
    fn save(&self, _: &PersistedState) {}
    fn audit(&self, entry: &AuditEntry) {
        lock(&self.audit_log).push(entry.clone());
    }
    fn read_audit(&self, limit: usize) -> Vec<AuditEntry> {
        let log = lock(&self.audit_log);
        log[log.len().saturating_sub(limit)..].to_vec()
    }
}

/// `defense.json` (atomic rewrite) and `audit.jsonl` (append-only, rotated at 20 MB) in one folder.
pub struct JsonPersistence {
    dir: PathBuf,
}

impl JsonPersistence {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl Persistence for JsonPersistence {
    fn load(&self) -> PersistedState {
        match fs::read_to_string(self.dir.join("defense.json")) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|err| {
                tracing::warn!(%err, "defense.json is unreadable; starting from the defaults");
                PersistedState::default()
            }),
            Err(_) => PersistedState::default(),
        }
    }

    fn save(&self, state: &PersistedState) {
        let write = || -> std::io::Result<()> {
            fs::create_dir_all(&self.dir)?;
            let tmp = self.dir.join("defense.json.tmp");
            fs::write(
                &tmp,
                serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?,
            )?;
            fs::rename(tmp, self.dir.join("defense.json"))
        };
        if let Err(err) = write() {
            tracing::error!(%err, "could not save defense.json");
        }
    }

    fn audit(&self, entry: &AuditEntry) {
        let Ok(line) = serde_json::to_string(entry) else {
            return;
        };
        let path = self.dir.join("audit.jsonl");
        let _ = fs::create_dir_all(&self.dir);
        if fs::metadata(&path).is_ok_and(|m| m.len() > AUDIT_MAX_BYTES) {
            let _ = fs::rename(&path, self.dir.join("audit.jsonl.1"));
        }
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }

    fn read_audit(&self, limit: usize) -> Vec<AuditEntry> {
        // The current file, then the rotated one when the current is too short.
        let mut entries: Vec<AuditEntry> = Vec::new();
        for name in ["audit.jsonl", "audit.jsonl.1"] {
            let Ok(text) = fs::read_to_string(self.dir.join(name)) else {
                continue;
            };
            let mut chunk: Vec<AuditEntry> = text
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            chunk.extend(entries);
            entries = chunk;
            if entries.len() >= limit {
                break;
            }
        }
        entries.split_off(entries.len().saturating_sub(limit))
    }
}

// ---- the protected set ----------------------------------------------------------------------------

/// Everything the Guardian and the block manager must never block, with the reason for each.
pub fn protected_entries(
    context: &NetworkContext,
    rdp_trusted: &[String],
    allowlist: &AllowlistConfig,
) -> Vec<ProtectedEntry> {
    let mut entries = vec![
        ProtectedEntry {
            cidr: "127.0.0.0/8".to_owned(),
            reason: "loopback".to_owned(),
        },
        ProtectedEntry {
            cidr: "::1/128".to_owned(),
            reason: "loopback".to_owned(),
        },
    ];
    let mut push = |text: &str, reason: &str| {
        if let Ok(block) = text.parse::<Cidr>() {
            entries.push(ProtectedEntry {
                cidr: format_cidr(&block),
                reason: reason.to_owned(),
            });
        }
    };
    for ip in &context.gateways {
        push(&ip.to_string(), "gateway");
    }
    for ip in &context.dns_servers {
        push(&ip.to_string(), "dns");
    }
    for ip in rdp_trusted {
        push(ip, "rdp_client");
    }
    for item in &allowlist.allowlist {
        push(item, "allowlist");
    }
    for item in &allowlist.management {
        push(item, "management");
    }
    entries
}

pub fn protected_set(entries: &[ProtectedEntry]) -> CidrSet {
    let mut set = CidrSet::new();
    for entry in entries {
        let _ = set.insert_str(&entry.cidr);
    }
    set
}

/// Why `target` may not be blocked, or `None`.
fn why_protected(target: &Cidr, entries: &[ProtectedEntry]) -> Option<String> {
    let span = cidr_span(target);
    for entry in entries {
        if let Ok(block) = entry.cidr.parse::<Cidr>() {
            if cidr_span(&block).overlaps(&span) {
                return Some(entry.reason.clone());
            }
        }
    }
    // The built-in floor (link-local, multicast, unspecified) that the firewall layer always keeps.
    if ProtectedSpans::new(&CidrSet::new()).overlaps(&span) {
        return Some("reserved".to_owned());
    }
    None
}

// ---- state ----------------------------------------------------------------------------------------

struct BlockEntry {
    manual: bool,
    reason: String,
    created_secs: u64,
    expires_secs: Option<u64>,
    alert_id: Option<u64>,
    escalation: u8,
}

struct State {
    blocks: HashMap<Cidr, BlockEntry>,
    policy: GuardianPolicy,
    allowlist: AllowlistConfig,
    decisions: VecDeque<GuardianDecision>,
    /// Unix seconds of the automatic blocks of the last hour.
    recent_auto: VecDeque<u64>,
    circuit_open: bool,
    escalation: BTreeMap<String, (u8, u64)>,
    /// Incident ids the Guardian already decided about: an incident escalating from High to
    /// Critical must not be blocked (and escalated in the ladder) twice.
    acted: VecDeque<u64>,
}

pub struct Defense {
    firewall: Arc<dyn Firewall>,
    persistence: Arc<dyn Persistence>,
    context: Arc<RwLock<NetworkContext>>,
    trust: Arc<TrustState>,
    state: Mutex<State>,
    clock: fn() -> u64,
}

impl Defense {
    pub fn new(
        firewall: Arc<dyn Firewall>,
        persistence: Arc<dyn Persistence>,
        context: Arc<RwLock<NetworkContext>>,
        trust: Arc<TrustState>,
    ) -> Self {
        Self::with_clock(firewall, persistence, context, trust, now_secs)
    }

    pub fn with_clock(
        firewall: Arc<dyn Firewall>,
        persistence: Arc<dyn Persistence>,
        context: Arc<RwLock<NetworkContext>>,
        trust: Arc<TrustState>,
        clock: fn() -> u64,
    ) -> Self {
        let saved = persistence.load();
        let mut blocks = HashMap::new();
        for stored in saved.blocks {
            if let Ok(cidr) = stored.cidr.parse::<Cidr>() {
                blocks.insert(
                    cidr,
                    BlockEntry {
                        manual: stored.manual,
                        reason: stored.reason,
                        created_secs: stored.created_secs,
                        expires_secs: stored.expires_secs,
                        alert_id: stored.alert_id,
                        escalation: stored.escalation,
                    },
                );
            }
        }
        // A fresh install starts in Monitor; a saved policy is clamped like any other.
        let policy = saved
            .policy
            .and_then(|p| sanitize_policy(p).ok())
            .unwrap_or_default();
        Self {
            firewall,
            persistence,
            context,
            trust,
            state: Mutex::new(State {
                blocks,
                policy,
                allowlist: saved.allowlist,
                decisions: VecDeque::new(),
                recent_auto: VecDeque::new(),
                circuit_open: false,
                escalation: saved.escalation,
                acted: VecDeque::new(),
            }),
            clock,
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn audit(&self, actor: &str, action: &str, target: &str, detail: &str, result: &str) {
        self.persistence.audit(&AuditEntry {
            unix_ms: self.now() * 1000,
            actor: actor.to_owned(),
            action: action.to_owned(),
            target: target.to_owned(),
            detail: detail.to_owned(),
            result: result.to_owned(),
        });
    }

    /// The newest audit entries matching `search` (case-insensitive over every field), newest first.
    pub fn audit_entries(&self, limit: usize, search: Option<&str>) -> (Vec<AuditEntry>, bool) {
        let needle = search.map(str::to_lowercase).filter(|s| !s.is_empty());
        // Searching reads more so that a filter can still fill the page.
        let all = self
            .persistence
            .read_audit(if needle.is_some() { 20_000 } else { limit + 1 });
        let mut matched: Vec<AuditEntry> = all
            .into_iter()
            .rev()
            .filter(|e| {
                needle.as_deref().is_none_or(|n| {
                    [&e.actor, &e.action, &e.target, &e.detail, &e.result]
                        .iter()
                        .any(|f| f.to_lowercase().contains(n))
                })
            })
            .collect();
        let truncated = matched.len() > limit;
        matched.truncate(limit);
        (matched, truncated)
    }

    /// The addresses that must never be blocked, as a set (for the blocklists and the Guardian).
    pub fn protected_set(&self) -> CidrSet {
        protected_set(&self.protected())
    }

    /// Why `target` may not be blocked right now, or `None`. Used by the MCP pre-check so a refused
    /// request never even becomes a pending approval.
    pub fn refusal_reason(&self, target: &str) -> Option<String> {
        let cidr = target.trim().parse::<Cidr>().ok()?;
        why_protected(&cidr, &self.protected())
    }

    /// Makes the firewall batch of a blocklist hold exactly `blocks` (protected addresses are carved
    /// out by the firewall layer as well). Failures are logged: a list that cannot be applied must
    /// not stop the others.
    pub fn apply_list(&self, id: &str, blocks: &[Cidr]) {
        let Ok(batch) = BatchId::list(id) else { return };
        // Nothing to apply and nothing there: do not touch the firewall.
        if blocks.is_empty()
            && self
                .firewall
                .list_blocks(&batch)
                .map_or(true, |b| b.is_empty())
        {
            return;
        }
        let protected = self.protected_set();
        let opts = BlockOptions::new(&protected).skip_protected();
        match self.firewall.apply_blocklist(&batch, blocks, &opts) {
            Ok(outcome) => {
                if !outcome.added.is_empty() || !outcome.removed.is_empty() {
                    self.audit(
                        "blocklist",
                        "apply_list",
                        id,
                        &format!(
                            "{} blocks, {} rules written",
                            outcome.total_blocked, outcome.rule_writes
                        ),
                        "ok",
                    );
                }
            }
            Err(err) => {
                tracing::warn!(list = id, %err, "could not apply the blocklist");
                self.audit("blocklist", "apply_list", id, &err.to_string(), "failed");
            }
        }
    }

    /// Removes the firewall rules of a blocklist that was switched off.
    pub fn clear_list(&self, id: &str) {
        let Ok(batch) = BatchId::list(id) else { return };
        if self
            .firewall
            .list_blocks(&batch)
            .map_or(true, |b| b.is_empty())
        {
            return;
        }
        match self.firewall.clear_batch(&batch) {
            Ok(removed) => self.audit(
                "blocklist",
                "clear_list",
                id,
                &format!("{removed} rules"),
                "ok",
            ),
            Err(err) => {
                tracing::warn!(list = id, %err, "could not clear the blocklist");
                self.audit("blocklist", "clear_list", id, &err.to_string(), "failed");
            }
        }
    }

    /// Adds an entry to the audit log on behalf of another part of the engine (RDP Shield).
    pub fn audit_entry(&self, actor: &str, action: &str, target: &str, detail: &str, result: &str) {
        self.audit(actor, action, target, detail, result);
    }

    fn persist(&self, state: &State) {
        self.persistence.save(&PersistedState {
            blocks: state
                .blocks
                .iter()
                .map(|(cidr, b)| StoredBlock {
                    cidr: format_cidr(cidr),
                    manual: b.manual,
                    reason: b.reason.clone(),
                    created_secs: b.created_secs,
                    expires_secs: b.expires_secs,
                    alert_id: b.alert_id,
                    escalation: b.escalation,
                })
                .collect(),
            policy: Some(state.policy.clone()),
            allowlist: state.allowlist.clone(),
            escalation: state.escalation.clone(),
        });
    }

    /// The current protected entries (gateway/DNS from the machine, trusted RDP clients, config).
    pub fn protected(&self) -> Vec<ProtectedEntry> {
        let trusted: Vec<String> = self
            .trust
            .addresses(self.now().saturating_mul(1000))
            .into_iter()
            .map(|a| a.addr)
            .collect();
        let context = self
            .context
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        protected_entries(&context, &trusted, &lock(&self.state).allowlist)
    }

    // ---- blocks -------------------------------------------------------------------------------

    fn block_views(state: &State) -> Vec<BlockView> {
        let mut views: Vec<BlockView> = state
            .blocks
            .iter()
            .map(|(cidr, b)| BlockView {
                cidr: format_cidr(cidr),
                source: if b.manual {
                    BlockSource::Manual
                } else {
                    BlockSource::Guardian
                },
                reason: b.reason.clone(),
                created_unix_ms: b.created_secs * 1000,
                expires_unix_ms: b.expires_secs.map(|s| s * 1000),
                alert_id: b.alert_id,
                escalation: b.escalation,
            })
            .collect();
        views.sort_by_key(|v| std::cmp::Reverse(v.created_unix_ms));
        views
    }

    pub fn list_blocks(&self) -> BlockList {
        let state = lock(&self.state);
        let manual = state.blocks.values().filter(|b| b.manual).count();
        let auto = state.blocks.len() - manual;
        let per_rule = pw_firewall::DEFAULT_MAX_PER_RULE;
        BlockList {
            blocks: Self::block_views(&state),
            rules_used: (manual.div_ceil(per_rule) + auto.div_ceil(per_rule)) as u32,
        }
    }

    /// Applies the desired blocks to Windows Firewall (blocking calls: run off the async workers).
    /// Expired blocks are dropped first; blocks that became protected are evicted.
    pub fn reconcile(&self) -> Result<(), ErrorPayload> {
        let now = self.now();
        let entries = self.protected();
        let protected = protected_set(&entries);
        let (manual, auto) = {
            let mut state = lock(&self.state);
            let before = state.blocks.len();
            state
                .blocks
                .retain(|_, b| b.expires_secs.is_none_or(|e| e > now));
            let expired = before - state.blocks.len();
            if expired > 0 {
                self.persist(&state);
                drop(state);
                self.audit("agent", "expire", "-", &format!("{expired} blocks"), "ok");
                state = lock(&self.state);
            }
            let split = |manual: bool| -> Vec<DesiredBlock> {
                state
                    .blocks
                    .iter()
                    .filter(|(_, b)| b.manual == manual)
                    .map(|(cidr, b)| DesiredBlock {
                        block: *cidr,
                        expires_at: b.expires_secs,
                    })
                    .collect()
            };
            (split(true), split(false))
        };
        let opts = BlockOptions::new(&protected).skip_protected();
        let mut evicted = Vec::new();
        for (batch, desired) in [(BatchId::manual(), manual), (BatchId::auto_block(), auto)] {
            // Nothing desired and nothing there: do not touch the firewall at all.
            if desired.is_empty()
                && self
                    .firewall
                    .list_blocks(&batch)
                    .map_or(true, |b| b.is_empty())
            {
                continue;
            }
            let outcome = self
                .firewall
                .reconcile_blocks(&batch, &desired, now, &opts)
                .map_err(firewall_error)?;
            evicted.extend(outcome.evicted_protected);
            evicted.extend(outcome.skipped_protected);
        }
        if !evicted.is_empty() {
            let mut state = lock(&self.state);
            for cidr in &evicted {
                state.blocks.remove(cidr);
            }
            self.persist(&state);
            drop(state);
            self.audit(
                "agent",
                "evict_protected",
                &evicted
                    .iter()
                    .map(format_cidr)
                    .collect::<Vec<_>>()
                    .join(","),
                "became protected",
                "ok",
            );
        }
        Ok(())
    }

    fn parse_targets(targets: &[String]) -> Result<Vec<Cidr>, ErrorPayload> {
        if targets.is_empty() {
            return Err(bad_request("nothing to block: give at least one address"));
        }
        if targets.len() > MAX_TARGETS_PER_REQUEST {
            return Err(bad_request(format!(
                "at most {MAX_TARGETS_PER_REQUEST} addresses at once"
            )));
        }
        targets
            .iter()
            .map(|t| {
                t.trim()
                    .parse::<Cidr>()
                    .map_err(|_| bad_request(format!("{t:?} is not an IP address or CIDR block")))
            })
            .collect()
    }

    /// Adds blocks. Protected addresses and ranges that are too wide are refused and reported.
    pub fn block(&self, request: &BlockRequest, actor: &str) -> Result<BlockResult, ErrorPayload> {
        if request.allow_broad {
            return Err(bad_request(
                "blocks wider than /8 (IPv4) or /16 (IPv6) are not supported",
            ));
        }
        if let Some(ttl) = request.ttl_secs {
            if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
                return Err(bad_request(
                    "the duration must be between 1 minute and 30 days",
                ));
            }
        }
        let targets = Self::parse_targets(&request.targets)?;
        let entries = self.protected();
        let mut result = BlockResult::default();
        let mut accepted = Vec::new();
        for target in targets {
            if let Some(reason) = why_protected(&target, &entries) {
                result.refused_protected.push(BlockRefusal {
                    target: format_cidr(&target),
                    reason,
                });
            } else if is_too_broad(&target) {
                result.refused_broad.push(format_cidr(&target));
            } else {
                accepted.push(target);
            }
        }
        if !accepted.is_empty() {
            let now = self.now();
            let mut state = lock(&self.state);
            if state.blocks.len() + accepted.len() > MAX_BLOCKS {
                return Err(bad_request("too many blocks; remove some first"));
            }
            for cidr in &accepted {
                state.blocks.insert(
                    *cidr,
                    BlockEntry {
                        manual: true,
                        reason: request.reason.clone(),
                        created_secs: now,
                        expires_secs: request.ttl_secs.map(|t| now + t),
                        alert_id: None,
                        escalation: 0,
                    },
                );
                result.blocked.push(format_cidr(cidr));
            }
            self.persist(&state);
        }
        for refusal in &result.refused_protected {
            self.audit(actor, "block", &refusal.target, &refusal.reason, "refused");
        }
        if !result.blocked.is_empty() {
            self.audit(
                actor,
                "block",
                &result.blocked.join(","),
                &request.reason,
                "ok",
            );
            self.reconcile()?;
        }
        Ok(result)
    }

    pub fn unblock(&self, targets: &[String], actor: &str) -> Result<BlockList, ErrorPayload> {
        let cidrs = Self::parse_targets(targets)?;
        {
            let mut state = lock(&self.state);
            for cidr in &cidrs {
                state.blocks.remove(cidr);
            }
            self.persist(&state);
        }
        self.audit(actor, "unblock", &targets.join(","), "", "ok");
        self.reconcile()?;
        Ok(self.list_blocks())
    }

    /// Removes every block of this app (manual and automatic) and their firewall rules.
    pub fn unblock_all(&self, actor: &str) -> Result<BlockList, ErrorPayload> {
        {
            let mut state = lock(&self.state);
            state.blocks.clear();
            self.persist(&state);
        }
        self.audit(actor, "unblock_all", "-", "", "ok");
        for batch in [BatchId::manual(), BatchId::auto_block()] {
            self.firewall.clear_batch(&batch).map_err(firewall_error)?;
        }
        Ok(self.list_blocks())
    }

    // ---- rules --------------------------------------------------------------------------------

    pub fn rules(&self, request: &FirewallRulesRequest) -> Result<FirewallRules, ErrorPayload> {
        let filter = RuleFilter::default();
        let all = self.firewall.list_rules(&filter).map_err(firewall_error)?;
        let text = request.text.as_deref().map(str::to_lowercase);
        let address = request
            .address
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty());
        let mut matched: Vec<FirewallRuleView> = all
            .iter()
            .filter(|r| !request.managed_only || r.is_managed())
            .filter(|r| {
                request.direction.is_none_or(|d| {
                    r.direction
                        == match d {
                            RuleDirection::Inbound => pw_firewall::Direction::Inbound,
                            RuleDirection::Outbound => pw_firewall::Direction::Outbound,
                        }
                })
            })
            .filter(|r| request.enabled.is_none_or(|e| r.enabled == e))
            .filter(|r| {
                text.as_deref().is_none_or(|t| {
                    [&r.name, &r.description, &r.grouping]
                        .iter()
                        .any(|s| s.to_lowercase().contains(t))
                        || r.application
                            .as_deref()
                            .is_some_and(|a| a.to_lowercase().contains(t))
                })
            })
            .filter(|r| {
                request.port.is_none_or(|p| {
                    pw_firewall::addr::ports_include(&r.local_ports, p)
                        || pw_firewall::addr::ports_include(&r.remote_ports, p)
                })
            })
            .filter(|r| {
                address
                    .is_none_or(|a| r.local_addresses.contains(a) || r.remote_addresses.contains(a))
            })
            .map(rule_view)
            .collect();
        matched.sort_by_key(|r| r.name.to_lowercase());
        let total = matched.len() as u32;
        let truncated = matched.len() > MAX_RULES_SHOWN;
        matched.truncate(MAX_RULES_SHOWN);
        Ok(FirewallRules {
            rules: matched,
            total,
            truncated,
        })
    }

    fn confirmation(text: &Option<String>) -> Result<Option<Confirmation>, ErrorPayload> {
        text.as_deref()
            .map(|t| Confirmation::from_phrase(t).map_err(firewall_error))
            .transpose()
    }

    pub fn add_rule(&self, edit: &FirewallRuleEdit, actor: &str) -> Result<(), ErrorPayload> {
        let rule = rule_from_view(&edit.rule)?;
        let confirmation = Self::confirmation(&edit.confirmation)?;
        let protected = protected_set(&self.protected());
        let mut opts = RuleOptions::default().protecting(&protected);
        if let Some(c) = &confirmation {
            opts = opts.confirmed(c);
        }
        let result = self.firewall.add_rule(&rule, &opts);
        self.audit(
            actor,
            "rule_add",
            &rule.name,
            "",
            if result.is_ok() { "ok" } else { "refused" },
        );
        result.map_err(firewall_error)
    }

    pub fn update_rule(&self, edit: &FirewallRuleEdit, actor: &str) -> Result<(), ErrorPayload> {
        let rule = rule_from_view(&edit.rule)?;
        let confirmation = Self::confirmation(&edit.confirmation)?;
        let protected = protected_set(&self.protected());
        let mut opts = RuleOptions::default().protecting(&protected);
        opts.allow_foreign_edit = edit.allow_foreign_edit;
        if let Some(c) = &confirmation {
            opts = opts.confirmed(c);
        }
        let result = self.firewall.update_rule(&rule.name, &rule, &opts);
        self.audit(
            actor,
            "rule_update",
            &rule.name,
            "",
            if result.is_ok() { "ok" } else { "refused" },
        );
        result.map_err(firewall_error)
    }

    pub fn remove_rule(
        &self,
        action: &FirewallRuleAction,
        actor: &str,
    ) -> Result<(), ErrorPayload> {
        let confirmation = Self::confirmation(&action.confirmation)?;
        let mut opts = RuleOptions {
            allow_foreign_edit: action.allow_foreign_edit,
            ..RuleOptions::default()
        };
        if let Some(c) = &confirmation {
            opts = opts.confirmed(c);
        }
        let result = self.firewall.remove_rule(&action.name, &opts);
        self.audit(
            actor,
            "rule_remove",
            &action.name,
            "",
            if result.is_ok() { "ok" } else { "refused" },
        );
        result.map_err(firewall_error)
    }

    pub fn enable_rule(
        &self,
        action: &FirewallRuleAction,
        actor: &str,
    ) -> Result<(), ErrorPayload> {
        let confirmation = Self::confirmation(&action.confirmation)?;
        let mut opts = RuleOptions {
            allow_foreign_edit: action.allow_foreign_edit,
            ..RuleOptions::default()
        };
        if let Some(c) = &confirmation {
            opts = opts.confirmed(c);
        }
        let result = self
            .firewall
            .set_enabled(&action.name, action.enabled, &opts);
        let what = if action.enabled {
            "rule_enable"
        } else {
            "rule_disable"
        };
        self.audit(
            actor,
            what,
            &action.name,
            "",
            if result.is_ok() { "ok" } else { "refused" },
        );
        result.map_err(firewall_error)
    }

    /// Removes every PacketWard rule (the blocks too). Needs the typed phrase when a PacketWard RDP
    /// rule exists.
    pub fn purge(&self, request: &PurgeRequest, actor: &str) -> Result<PurgeResult, ErrorPayload> {
        let confirmation = Self::confirmation(&request.confirmation)?;
        let mut opts = RuleOptions::default();
        if let Some(c) = &confirmation {
            opts = opts.confirmed(c);
        }
        let report = self.firewall.purge(&opts);
        self.audit(
            actor,
            "purge",
            "-",
            "",
            if report.is_ok() { "ok" } else { "refused" },
        );
        let report = report.map_err(firewall_error)?;
        let mut state = lock(&self.state);
        state.blocks.clear();
        self.persist(&state);
        Ok(PurgeResult {
            removed_rules: report.removed,
        })
    }

    // ---- Guardian -----------------------------------------------------------------------------

    pub fn status(&self) -> GuardianStatus {
        let protected = self.protected();
        let now = self.now();
        let mut state = lock(&self.state);
        trim_recent(&mut state, now);
        let would_block = state
            .decisions
            .iter()
            .filter(|d| d.outcome == "would_block" && d.unix_ms / 1000 + DAY_SECS > now)
            .map(|d| d.source.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u32;
        GuardianStatus {
            policy: state.policy.clone(),
            circuit_open: state.circuit_open,
            blocks_last_hour: state.recent_auto.len() as u32,
            protected,
            decisions: state.decisions.iter().cloned().collect(),
            would_block_24h: would_block,
        }
    }

    pub fn policy(&self) -> GuardianPolicy {
        lock(&self.state).policy.clone()
    }

    pub fn set_policy(
        &self,
        request: &SetGuardianPolicy,
        actor: &str,
    ) -> Result<GuardianStatus, ErrorPayload> {
        let policy = sanitize_policy(request.policy.clone())?;
        if policy.mode == GuardianMode::Active && !request.confirm_active {
            return Err(bad_request(
                "switching the Guardian to Active needs an explicit confirmation",
            ));
        }
        {
            let mut state = lock(&self.state);
            let changed = state.policy != policy;
            state.policy = policy.clone();
            if policy.mode != GuardianMode::Active {
                state.circuit_open = false;
            }
            self.persist(&state);
            if changed {
                drop(state);
                self.audit(
                    actor,
                    "guardian_policy",
                    "-",
                    &format!("{:?}", policy.mode).to_lowercase(),
                    "ok",
                );
            }
        }
        Ok(self.status())
    }

    pub fn allowlist(&self) -> AllowlistConfig {
        lock(&self.state).allowlist.clone()
    }

    pub fn set_allowlist(
        &self,
        config: AllowlistConfig,
        actor: &str,
    ) -> Result<AllowlistConfig, ErrorPayload> {
        for item in config.allowlist.iter().chain(&config.management) {
            item.trim()
                .parse::<Cidr>()
                .map_err(|_| bad_request(format!("{item:?} is not an IP address or CIDR block")))?;
        }
        let clean = AllowlistConfig {
            allowlist: config
                .allowlist
                .iter()
                .map(|s| s.trim().to_owned())
                .collect(),
            management: config
                .management
                .iter()
                .map(|s| s.trim().to_owned())
                .collect(),
        };
        {
            let mut state = lock(&self.state);
            state.allowlist = clean.clone();
            self.persist(&state);
        }
        self.audit(
            actor,
            "allowlist",
            "-",
            &format!("{} entries", clean.allowlist.len()),
            "ok",
        );
        // Newly protected addresses must come out of the firewall right away.
        self.reconcile()?;
        Ok(clean)
    }

    fn record_decision(&self, decision: GuardianDecision, remember: bool) {
        let mut state = lock(&self.state);
        // Below-threshold and failed attempts may still be acted on later (escalation, retry).
        if remember
            && !matches!(
                decision.outcome.as_str(),
                "skipped_below_threshold" | "skipped_failed"
            )
        {
            state.acted.push_back(decision.alert_id);
            while state.acted.len() > 2000 {
                state.acted.pop_front();
            }
        }
        state.decisions.push_front(decision);
        while state.decisions.len() > MAX_DECISIONS {
            state.decisions.pop_back();
        }
    }

    /// The Guardian's reaction to one alert event. Returns the decision, if the alert called for one.
    pub fn on_alert(&self, alert: &AlertView) -> Option<GuardianDecision> {
        if alert.phase == AlertPhaseView::Ended {
            return None;
        }
        let source = alert.source.clone()?;
        let policy = self.policy();
        if policy.mode == GuardianMode::Off {
            return None;
        }
        if lock(&self.state).acted.contains(&alert.id) {
            return None;
        }
        let now = self.now();
        let mut decision = GuardianDecision {
            unix_ms: now * 1000,
            source: source.clone(),
            alert_id: alert.id,
            summary_key: alert.summary_key.clone(),
            severity: alert.severity,
            outcome: String::new(),
            ttl_secs: None,
            why: String::new(),
        };
        // Password guessing against RDP is what automatic blocking is for: it qualifies from Medium
        // on even when the general threshold is higher.
        let threshold = if alert.summary_key == "rdp_brute_force" {
            policy.min_severity.min(AlertSeverity::Medium)
        } else {
            policy.min_severity
        };
        if alert.severity < threshold {
            decision.outcome = "skipped_below_threshold".to_owned();
            decision.why = "the alert is below the severity the Guardian acts on".to_owned();
            self.record_decision(decision.clone(), true);
            return Some(decision);
        }
        let Ok(address) = source.parse::<IpAddr>() else {
            return None;
        };
        let target = Cidr::new(address, if address.is_ipv4() { 32 } else { 128 }).ok()?;
        let act = Act {
            alert_id: Some(alert.id),
            label: format!("{} (severity {:?})", alert.summary_key, alert.severity),
            block_reason: None,
            escalate: true,
        };
        Some(self.act(decision, target, &source, &policy, &act))
    }

    /// Guards one address on behalf of a reactive rule that is not an alert (the RDP country
    /// restriction): the same protected-set check, Monitor report, TTL ladder (first step: these
    /// blocks never escalate), circuit breaker, audit and firewall path as an alert. `summary_key`
    /// is what the decision shows (`rdp_country`), `block_reason` what the block is labelled with
    /// (`rdp_country:CN`). Returns `None` when the Guardian is Off or the address is not valid.
    pub fn guard_address(
        &self,
        address: IpAddr,
        summary_key: &str,
        block_reason: &str,
    ) -> Option<GuardianDecision> {
        let policy = self.policy();
        if policy.mode == GuardianMode::Off {
            return None;
        }
        let target = Cidr::new(address, if address.is_ipv4() { 32 } else { 128 }).ok()?;
        let source = address.to_string();
        let decision = GuardianDecision {
            unix_ms: self.now() * 1000,
            source: source.clone(),
            alert_id: 0,
            summary_key: summary_key.to_owned(),
            severity: AlertSeverity::Medium,
            outcome: String::new(),
            ttl_secs: None,
            why: String::new(),
        };
        let act = Act {
            alert_id: None,
            label: block_reason.to_owned(),
            block_reason: Some(block_reason.to_owned()),
            escalate: false,
        };
        Some(self.act(decision, target, &source, &policy, &act))
    }

    /// The decision tail shared by alerts and reactive rules: protected check, ladder step, Monitor
    /// report, circuit breaker, block, audit.
    fn act(
        &self,
        mut decision: GuardianDecision,
        target: Cidr,
        source: &str,
        policy: &GuardianPolicy,
        act: &Act,
    ) -> GuardianDecision {
        let now = self.now();
        let remember = act.alert_id.is_some();
        // Re-check the protected set now; the alert's own flag may be stale.
        if let Some(reason) = why_protected(&target, &self.protected()) {
            decision.outcome = "skipped_protected".to_owned();
            decision.why = format!("{source} is protected ({reason}) and is never blocked");
            self.audit("guardian", "block", source, &reason, "refused");
            self.record_decision(decision.clone(), remember);
            return decision;
        }
        let (ttl, level) = {
            let state = lock(&self.state);
            let previous = if act.escalate {
                state
                    .escalation
                    .get(source)
                    .filter(|(_, at)| at + ESCALATION_MEMORY_SECS > now)
                    .map_or(0, |(level, _)| *level)
            } else {
                0
            };
            let step = usize::from(previous).min(policy.ttl_ladder_secs.len().saturating_sub(1));
            (
                policy.ttl_ladder_secs.get(step).copied().unwrap_or(15 * 60),
                previous.saturating_add(u8::from(act.escalate)),
            )
        };
        decision.ttl_secs = Some(ttl);
        let why = format!("{}: {}; blocked for {} min", source, act.label, ttl / 60);
        if policy.mode == GuardianMode::Monitor {
            decision.outcome = "would_block".to_owned();
            decision.why = why;
            self.audit("guardian", "would_block", source, &decision.why, "ok");
            self.record_decision(decision.clone(), remember);
            return decision;
        }
        // Active: the circuit breaker first.
        {
            let mut state = lock(&self.state);
            trim_recent(&mut state, now);
            if state.recent_auto.len() as u32 >= policy.max_blocks_per_hour {
                state.circuit_open = true;
                drop(state);
                decision.outcome = "skipped_circuit".to_owned();
                decision.why = format!(
                    "the circuit breaker is open ({} automatic blocks in the last hour)",
                    policy.max_blocks_per_hour
                );
                self.audit("guardian", "circuit_open", source, &decision.why, "refused");
                self.record_decision(decision.clone(), remember);
                return decision;
            }
            state.circuit_open = false;
            state.blocks.insert(
                target,
                BlockEntry {
                    manual: false,
                    reason: act.block_reason.clone().unwrap_or_else(|| why.clone()),
                    created_secs: now,
                    expires_secs: Some(now + ttl),
                    alert_id: act.alert_id,
                    escalation: level,
                },
            );
            state.recent_auto.push_back(now);
            if act.escalate {
                state.escalation.insert(source.to_owned(), (level, now));
                state
                    .escalation
                    .retain(|_, (_, at)| *at + ESCALATION_MEMORY_SECS > now);
            }
            self.persist(&state);
        }
        match self.reconcile() {
            Ok(()) => {
                decision.outcome = "blocked".to_owned();
                decision.why = why;
                self.audit("guardian", "block", source, &decision.why, "ok");
            }
            Err(err) => {
                // The block could not be applied: do not pretend, and do not keep a phantom entry.
                lock(&self.state).blocks.remove(&target);
                decision.outcome = "skipped_failed".to_owned();
                decision.why = format!("the firewall refused: {}", err.message);
                self.audit("guardian", "block", source, &decision.why, "failed");
            }
        }
        self.record_decision(decision.clone(), remember);
        decision
    }

    /// Distinct addresses the reactive rule `summary_key` blocked and would have blocked in the
    /// last 24 hours, from the Guardian's bounded decision list.
    pub fn decision_counts_24h(&self, summary_key: &str) -> (u32, u32) {
        let now = self.now();
        let state = lock(&self.state);
        let distinct = |outcome: &str| {
            state
                .decisions
                .iter()
                .filter(|d| {
                    d.summary_key == summary_key
                        && d.outcome == outcome
                        && d.unix_ms / 1000 + DAY_SECS > now
                })
                .map(|d| d.source.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len() as u32
        };
        (distinct("blocked"), distinct("would_block"))
    }
}

/// How one decision is taken: what labels it and whether it climbs the escalation ladder.
struct Act {
    /// The incident the decision belongs to (`None` for a reactive rule).
    alert_id: Option<u64>,
    /// What the explanation says it was for.
    label: String,
    /// The label of the block itself (default: the whole explanation).
    block_reason: Option<String>,
    escalate: bool,
}

fn trim_recent(state: &mut State, now: u64) {
    while state
        .recent_auto
        .front()
        .is_some_and(|t| t + HOUR_SECS <= now)
    {
        state.recent_auto.pop_front();
    }
    if state.circuit_open && state.recent_auto.is_empty() {
        state.circuit_open = false;
    }
}

/// Clamps the policy to safe ranges; a nonsensical one is an error, never silently "fixed" upward.
pub fn sanitize_policy(mut policy: GuardianPolicy) -> Result<GuardianPolicy, ErrorPayload> {
    if policy.ttl_ladder_secs.is_empty() || policy.ttl_ladder_secs.len() > MAX_LADDER_STEPS {
        return Err(bad_request(format!(
            "the block durations need 1 to {MAX_LADDER_STEPS} steps"
        )));
    }
    if policy
        .ttl_ladder_secs
        .iter()
        .any(|t| !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(t))
    {
        return Err(bad_request(
            "each block duration must be between 1 minute and 30 days",
        ));
    }
    if !(1..=500).contains(&policy.max_blocks_per_hour) {
        return Err(bad_request(
            "the circuit breaker limit must be between 1 and 500 per hour",
        ));
    }
    policy.ttl_ladder_secs.sort_unstable();
    Ok(policy)
}

// ---- rule conversions -----------------------------------------------------------------------------

fn protocol_text(protocol: Protocol) -> String {
    match protocol {
        Protocol::Any => "any".to_owned(),
        Protocol::Tcp => "tcp".to_owned(),
        Protocol::Udp => "udp".to_owned(),
        Protocol::Icmpv4 => "icmpv4".to_owned(),
        Protocol::Icmpv6 => "icmpv6".to_owned(),
        Protocol::Other(n) => n.to_string(),
    }
}

fn protocol_from(text: &str) -> Result<Protocol, ErrorPayload> {
    match text.trim().to_lowercase().as_str() {
        "any" | "*" | "" => Ok(Protocol::Any),
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmpv4" => Ok(Protocol::Icmpv4),
        "icmpv6" => Ok(Protocol::Icmpv6),
        other => other
            .parse::<u8>()
            .map(Protocol::Other)
            .map_err(|_| bad_request(format!("unknown protocol {other:?}"))),
    }
}

pub fn rule_view(rule: &Rule) -> FirewallRuleView {
    FirewallRuleView {
        name: rule.name.clone(),
        description: rule.description.clone(),
        group: rule.grouping.clone(),
        direction: match rule.direction {
            pw_firewall::Direction::Inbound => RuleDirection::Inbound,
            pw_firewall::Direction::Outbound => RuleDirection::Outbound,
        },
        action: match rule.action {
            pw_firewall::Action::Allow => RuleAction::Allow,
            pw_firewall::Action::Block => RuleAction::Block,
        },
        enabled: rule.enabled,
        protocol: protocol_text(rule.protocol),
        local_ports: rule.local_ports.clone(),
        remote_ports: rule.remote_ports.clone(),
        local_addresses: rule.local_addresses.clone(),
        remote_addresses: rule.remote_addresses.clone(),
        application: rule.application.clone(),
        service: rule.service.clone(),
        managed: rule.is_managed(),
        builtin_rdp: pw_firewall::guard::is_builtin_rdp_rule(rule),
    }
}

fn rule_from_view(view: &FirewallRuleView) -> Result<Rule, ErrorPayload> {
    let mut rule = Rule::new(
        &view.name,
        match view.direction {
            RuleDirection::Inbound => pw_firewall::Direction::Inbound,
            RuleDirection::Outbound => pw_firewall::Direction::Outbound,
        },
        match view.action {
            RuleAction::Allow => pw_firewall::Action::Allow,
            RuleAction::Block => pw_firewall::Action::Block,
        },
    );
    rule.description = view.description.clone();
    rule.grouping = view.group.clone();
    rule.enabled = view.enabled;
    rule.protocol = protocol_from(&view.protocol)?;
    rule.local_ports = view.local_ports.clone();
    rule.remote_ports = view.remote_ports.clone();
    rule.local_addresses = view.local_addresses.clone();
    rule.remote_addresses = view.remote_addresses.clone();
    rule.application = view.application.clone();
    rule.service = view.service.clone();
    Ok(rule)
}

#[allow(dead_code)]
fn severity_name(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Low => "low",
        AlertSeverity::Medium => "medium",
        AlertSeverity::High => "high",
        AlertSeverity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use pw_firewall::fake::FakeFirewall;
    use pw_firewall::FirewallManager;

    use super::*;

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(1_700_000_000) };
    }

    fn clock() -> u64 {
        NOW.with(Cell::get)
    }

    fn advance(secs: u64) {
        NOW.with(|n| n.set(n.get() + secs));
    }

    struct Rig {
        defense: Defense,
        firewall: Arc<FirewallManager<FakeFirewall>>,
        persistence: Arc<MemoryPersistence>,
        trust: Arc<TrustState>,
    }

    fn rig_with(persistence: Arc<dyn Persistence>) -> Rig {
        NOW.with(|n| n.set(now_secs()));
        let firewall = Arc::new(FirewallManager::new(FakeFirewall::windows_defaults()));
        let context = Arc::new(RwLock::new(NetworkContext {
            gateways: vec!["143.20.99.1".parse().unwrap()],
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
        }));
        let trust = TrustState::new(30);
        let defense = Defense::with_clock(
            Arc::clone(&firewall) as Arc<dyn Firewall>,
            persistence,
            context,
            Arc::clone(&trust),
            clock,
        );
        Rig {
            defense,
            firewall,
            persistence: Arc::new(MemoryPersistence::default()),
            trust,
        }
    }

    fn rig() -> Rig {
        let memory = Arc::new(MemoryPersistence::default());
        let mut rig = rig_with(Arc::clone(&memory) as Arc<dyn Persistence>);
        rig.persistence = memory;
        rig
    }

    fn alert(id: u64, source: &str, severity: AlertSeverity) -> AlertView {
        AlertView {
            id,
            phase: AlertPhaseView::Started,
            kind: pw_proto::AlertKindView::SynFlood,
            severity,
            source: Some(source.to_owned()),
            summary_key: "syn_flood".to_owned(),
            metrics: vec![],
            window_secs: 10,
            first_seen_unix_ms: 0,
            last_seen_unix_ms: 0,
            protected: false,
            peak_severity: severity,
        }
    }

    fn block(targets: &[&str], ttl: Option<u64>) -> BlockRequest {
        BlockRequest {
            targets: targets.iter().map(|t| (*t).to_owned()).collect(),
            ttl_secs: ttl,
            reason: "test".into(),
            allow_broad: false,
        }
    }

    fn active(rig: &Rig) {
        let policy = GuardianPolicy {
            mode: GuardianMode::Active,
            ..GuardianPolicy::default()
        };
        rig.defense
            .set_policy(
                &SetGuardianPolicy {
                    policy,
                    confirm_active: true,
                },
                "test",
            )
            .unwrap();
    }

    fn blocked_in_firewall(rig: &Rig) -> Vec<String> {
        let mut all = Vec::new();
        for batch in [BatchId::manual(), BatchId::auto_block()] {
            all.extend(
                rig.firewall
                    .list_blocks(&batch)
                    .unwrap()
                    .iter()
                    .map(format_cidr),
            );
        }
        all.sort();
        all
    }

    #[test]
    fn a_fresh_install_is_in_monitor_mode_and_touches_nothing() {
        let rig = rig();
        assert_eq!(rig.defense.policy().mode, GuardianMode::Monitor);
        rig.defense.reconcile().unwrap();
        assert!(rig.firewall.backend().writes().is_empty());
    }

    #[test]
    fn manual_blocks_reach_the_firewall_and_can_be_removed() {
        let rig = rig();
        let result = rig
            .defense
            .block(&block(&["203.0.113.7", "198.51.100.0/24"], None), "ui")
            .unwrap();
        assert_eq!(result.blocked.len(), 2);
        assert_eq!(
            blocked_in_firewall(&rig),
            ["198.51.100.0/24", "203.0.113.7/32"]
        );
        assert_eq!(rig.defense.list_blocks().blocks.len(), 2);

        rig.defense
            .unblock(&["203.0.113.7".to_owned()], "ui")
            .unwrap();
        assert_eq!(blocked_in_firewall(&rig), ["198.51.100.0/24"]);
        rig.defense.unblock_all("ui").unwrap();
        assert!(blocked_in_firewall(&rig).is_empty());
        assert!(rig.defense.list_blocks().blocks.is_empty());
    }

    #[test]
    fn protected_addresses_are_refused_with_the_reason() {
        let rig = rig();
        rig.trust.sink()(pw_netstat::logon::LogonEvent {
            addr: "198.51.100.77".parse().unwrap(),
            at_unix_ms: clock() * 1000,
        });
        let result = rig
            .defense
            .block(
                &block(
                    &[
                        "143.20.99.1",
                        "1.1.1.1",
                        "198.51.100.77",
                        "127.0.0.1",
                        "169.254.1.1",
                        "203.0.113.9",
                    ],
                    None,
                ),
                "ui",
            )
            .unwrap();
        assert_eq!(result.blocked, ["203.0.113.9/32"]);
        let reasons: BTreeMap<String, String> = result
            .refused_protected
            .into_iter()
            .map(|r| (r.target, r.reason))
            .collect();
        assert_eq!(reasons["143.20.99.1/32"], "gateway");
        assert_eq!(reasons["1.1.1.1/32"], "dns");
        assert_eq!(reasons["198.51.100.77/32"], "rdp_client");
        assert_eq!(reasons["127.0.0.1/32"], "loopback");
        assert_eq!(reasons["169.254.1.1/32"], "reserved");
        // A range that merely contains a protected address is refused too.
        let wide = rig
            .defense
            .block(&block(&["143.20.99.0/24"], None), "ui")
            .unwrap();
        assert!(wide.blocked.is_empty());
        assert_eq!(wide.refused_protected[0].reason, "gateway");
    }

    #[test]
    fn bad_requests_are_rejected_before_anything_is_stored() {
        let rig = rig();
        assert!(rig.defense.block(&block(&[], None), "ui").is_err());
        assert!(rig
            .defense
            .block(&block(&["not-an-ip"], None), "ui")
            .is_err());
        assert!(rig
            .defense
            .block(&block(&["203.0.113.1"], Some(5)), "ui")
            .is_err());
        let broad = rig
            .defense
            .block(&block(&["0.0.0.0/0", "10.0.0.0/7"], None), "ui")
            .unwrap();
        assert!(broad.blocked.is_empty());
        assert!(!broad.refused_broad.is_empty() || !broad.refused_protected.is_empty());
        let mut request = block(&["203.0.113.1"], None);
        request.allow_broad = true;
        assert!(rig.defense.block(&request, "ui").is_err());
        assert!(rig.defense.list_blocks().blocks.is_empty());
    }

    #[test]
    fn blocks_with_a_duration_expire_and_leave_the_firewall() {
        let rig = rig();
        rig.defense
            .block(&block(&["203.0.113.7"], Some(600)), "ui")
            .unwrap();
        assert_eq!(blocked_in_firewall(&rig), ["203.0.113.7/32"]);
        advance(599);
        rig.defense.reconcile().unwrap();
        assert_eq!(blocked_in_firewall(&rig), ["203.0.113.7/32"]);
        advance(2);
        rig.defense.reconcile().unwrap();
        assert!(blocked_in_firewall(&rig).is_empty());
        assert!(rig.defense.list_blocks().blocks.is_empty());
    }

    #[test]
    fn a_block_on_a_newly_protected_address_is_evicted() {
        let rig = rig();
        rig.defense
            .block(&block(&["203.0.113.50"], None), "ui")
            .unwrap();
        rig.defense
            .set_allowlist(
                AllowlistConfig {
                    allowlist: vec!["203.0.113.0/24".into()],
                    management: vec![],
                },
                "ui",
            )
            .unwrap();
        assert!(blocked_in_firewall(&rig).is_empty());
        assert!(rig.defense.list_blocks().blocks.is_empty());
    }

    #[test]
    fn monitor_mode_records_what_it_would_block_and_changes_nothing() {
        let rig = rig();
        let decision = rig
            .defense
            .on_alert(&alert(1, "203.0.113.9", AlertSeverity::High))
            .unwrap();
        assert_eq!(decision.outcome, "would_block");
        assert_eq!(decision.ttl_secs, Some(15 * 60));
        assert!(rig.firewall.backend().writes().is_empty());
        let status = rig.defense.status();
        assert_eq!(status.would_block_24h, 1);
        assert_eq!(status.decisions.len(), 1);
        assert!(status.decisions[0].why.contains("203.0.113.9"));
        // Alerts below the threshold and ended alerts are not decisions about blocking.
        let low = rig
            .defense
            .on_alert(&alert(2, "203.0.113.10", AlertSeverity::Medium))
            .unwrap();
        assert_eq!(low.outcome, "skipped_below_threshold");
        let mut ended = alert(3, "203.0.113.11", AlertSeverity::Critical);
        ended.phase = AlertPhaseView::Ended;
        assert!(rig.defense.on_alert(&ended).is_none());
        // Distributed attacks have no source to block.
        let mut distributed = alert(4, "x", AlertSeverity::Critical);
        distributed.source = None;
        assert!(rig.defense.on_alert(&distributed).is_none());
    }

    #[test]
    fn active_needs_an_explicit_confirmation() {
        let rig = rig();
        let policy = GuardianPolicy {
            mode: GuardianMode::Active,
            ..GuardianPolicy::default()
        };
        let err = rig
            .defense
            .set_policy(
                &SetGuardianPolicy {
                    policy,
                    confirm_active: false,
                },
                "ui",
            )
            .unwrap_err();
        assert!(err.message.contains("confirmation"));
        assert_eq!(rig.defense.policy().mode, GuardianMode::Monitor);
    }

    #[test]
    fn active_blocks_with_a_ttl_that_grows_for_repeat_offenders() {
        let rig = rig();
        active(&rig);
        let first = rig
            .defense
            .on_alert(&alert(1, "203.0.113.9", AlertSeverity::High))
            .unwrap();
        assert_eq!(first.outcome, "blocked");
        assert_eq!(first.ttl_secs, Some(900));
        assert_eq!(blocked_in_firewall(&rig), ["203.0.113.9/32"]);
        let views = rig.defense.list_blocks().blocks;
        assert_eq!(views[0].source, BlockSource::Guardian);
        assert_eq!(views[0].alert_id, Some(1));

        advance(901);
        rig.defense.reconcile().unwrap();
        assert!(blocked_in_firewall(&rig).is_empty());
        let second = rig
            .defense
            .on_alert(&alert(2, "203.0.113.9", AlertSeverity::High))
            .unwrap();
        assert_eq!(
            second.ttl_secs,
            Some(3600),
            "a repeat offender is blocked for longer"
        );
        advance(3601);
        rig.defense.reconcile().unwrap();
        let third = rig
            .defense
            .on_alert(&alert(3, "203.0.113.9", AlertSeverity::High))
            .unwrap();
        assert_eq!(third.ttl_secs, Some(86_400));
    }

    #[test]
    fn the_guardian_never_blocks_a_protected_source() {
        let rig = rig();
        active(&rig);
        rig.trust.sink()(pw_netstat::logon::LogonEvent {
            addr: "198.51.100.77".parse().unwrap(),
            at_unix_ms: clock() * 1000,
        });
        for (id, source, reason) in [
            (1, "198.51.100.77", "rdp_client"),
            (2, "143.20.99.1", "gateway"),
            (3, "1.1.1.1", "dns"),
        ] {
            let decision = rig
                .defense
                .on_alert(&alert(id, source, AlertSeverity::Critical))
                .unwrap();
            assert_eq!(decision.outcome, "skipped_protected", "{source}");
            assert!(decision.why.contains(reason), "{}", decision.why);
        }
        assert!(blocked_in_firewall(&rig).is_empty());
        assert!(rig.firewall.backend().writes().is_empty());
    }

    #[test]
    fn the_circuit_breaker_stops_automatic_blocks_and_resets() {
        let rig = rig();
        let policy = GuardianPolicy {
            mode: GuardianMode::Active,
            max_blocks_per_hour: 2,
            ..GuardianPolicy::default()
        };
        rig.defense
            .set_policy(
                &SetGuardianPolicy {
                    policy,
                    confirm_active: true,
                },
                "ui",
            )
            .unwrap();
        let outcome = |id: u64, ip: &str| {
            rig.defense
                .on_alert(&alert(id, ip, AlertSeverity::High))
                .unwrap()
                .outcome
        };
        assert_eq!(outcome(1, "203.0.113.1"), "blocked");
        assert_eq!(outcome(2, "203.0.113.2"), "blocked");
        assert_eq!(outcome(3, "203.0.113.3"), "skipped_circuit");
        assert!(rig.defense.status().circuit_open);
        assert_eq!(blocked_in_firewall(&rig).len(), 2);
        advance(3601);
        assert!(!rig.defense.status().circuit_open);
        assert_eq!(outcome(4, "203.0.113.4"), "blocked");
    }

    #[test]
    fn a_firewall_failure_is_reported_and_leaves_no_phantom_block() {
        let rig = rig();
        active(&rig);
        rig.firewall.backend().fail_writes_after(0);
        let decision = rig
            .defense
            .on_alert(&alert(1, "203.0.113.9", AlertSeverity::High))
            .unwrap();
        assert_eq!(decision.outcome, "skipped_failed");
        assert!(rig.defense.list_blocks().blocks.is_empty());
        rig.firewall.backend().heal();
    }

    #[test]
    fn every_block_decision_and_refusal_is_audited() {
        let rig = rig();
        rig.defense
            .block(&block(&["203.0.113.7", "143.20.99.1"], None), "pwctl")
            .unwrap();
        rig.defense.unblock_all("pwctl").unwrap();
        let log = lock(&rig.persistence.audit_log);
        let actions: Vec<(&str, &str, &str)> = log
            .iter()
            .map(|e| (e.actor.as_str(), e.action.as_str(), e.result.as_str()))
            .collect();
        assert!(actions.contains(&("pwctl", "block", "refused")));
        assert!(actions.contains(&("pwctl", "block", "ok")));
        assert!(actions.contains(&("pwctl", "unblock_all", "ok")));
    }

    #[test]
    fn policy_validation_rejects_unsafe_values() {
        let rig = rig();
        for policy in [
            GuardianPolicy {
                ttl_ladder_secs: vec![],
                ..GuardianPolicy::default()
            },
            GuardianPolicy {
                ttl_ladder_secs: vec![5],
                ..GuardianPolicy::default()
            },
            GuardianPolicy {
                ttl_ladder_secs: vec![60; 9],
                ..GuardianPolicy::default()
            },
            GuardianPolicy {
                max_blocks_per_hour: 0,
                ..GuardianPolicy::default()
            },
            GuardianPolicy {
                max_blocks_per_hour: 9999,
                ..GuardianPolicy::default()
            },
        ] {
            assert!(rig
                .defense
                .set_policy(
                    &SetGuardianPolicy {
                        policy,
                        confirm_active: true
                    },
                    "ui"
                )
                .is_err());
        }
    }

    #[test]
    fn blocks_the_policy_and_the_allowlist_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let rig = rig_with(Arc::new(JsonPersistence::new(dir.path().to_path_buf())));
            rig.defense
                .block(&block(&["203.0.113.7"], Some(3600)), "ui")
                .unwrap();
            rig.defense
                .set_allowlist(
                    AllowlistConfig {
                        allowlist: vec!["192.0.2.0/24".into()],
                        management: vec![],
                    },
                    "ui",
                )
                .unwrap();
            active(&rig);
        }
        // A new process: the firewall is rebuilt from what was saved.
        let rig = rig_with(Arc::new(JsonPersistence::new(dir.path().to_path_buf())));
        assert_eq!(rig.defense.policy().mode, GuardianMode::Active);
        assert_eq!(rig.defense.allowlist().allowlist, ["192.0.2.0/24"]);
        assert!(blocked_in_firewall(&rig).is_empty(), "nothing applied yet");
        rig.defense.reconcile().unwrap();
        assert_eq!(blocked_in_firewall(&rig), ["203.0.113.7/32"]);
        let audit = fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(audit.contains("\"action\":\"block\""));
    }

    #[test]
    fn a_corrupt_state_file_falls_back_to_safe_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("defense.json"), "{ not json").unwrap();
        let rig = rig_with(Arc::new(JsonPersistence::new(dir.path().to_path_buf())));
        assert_eq!(rig.defense.policy().mode, GuardianMode::Monitor);
        assert!(rig.defense.list_blocks().blocks.is_empty());
    }

    #[test]
    fn rules_can_be_listed_and_the_builtin_rdp_rules_are_guarded() {
        let rig = rig();
        let rules = rig.defense.rules(&FirewallRulesRequest::default()).unwrap();
        assert!(rules.total > 0 && !rules.truncated);
        let rdp: Vec<_> = rules.rules.iter().filter(|r| r.builtin_rdp).collect();
        assert!(
            !rdp.is_empty(),
            "the defaults include the built-in Remote Desktop rules"
        );
        let filtered = rig
            .defense
            .rules(&FirewallRulesRequest {
                text: Some("remote desktop".into()),
                ..FirewallRulesRequest::default()
            })
            .unwrap();
        assert!(!filtered.rules.is_empty() && filtered.total < rules.total);

        let name = rdp[0].name.clone();
        // Turning a built-in RDP rule off needs the typed confirmation, and foreign rules need the flag.
        let off = FirewallRuleAction {
            name: name.clone(),
            enabled: false,
            allow_foreign_edit: true,
            confirmation: None,
        };
        assert!(rig.defense.enable_rule(&off, "ui").is_err());
        let wrong = FirewallRuleAction {
            confirmation: Some("yes".into()),
            ..off.clone()
        };
        assert!(rig.defense.enable_rule(&wrong, "ui").is_err());
        assert!(rig
            .defense
            .rules(&FirewallRulesRequest::default())
            .unwrap()
            .rules
            .iter()
            .any(|r| r.name == name && r.enabled));
    }

    #[test]
    fn user_rules_get_the_packetward_group_and_purge_removes_only_ours() {
        let rig = rig();
        let edit = FirewallRuleEdit {
            rule: FirewallRuleView {
                name: "Allow office".into(),
                description: "test".into(),
                group: String::new(),
                direction: RuleDirection::Inbound,
                action: RuleAction::Allow,
                enabled: true,
                protocol: "tcp".into(),
                local_ports: "8080".into(),
                remote_ports: "*".into(),
                local_addresses: "*".into(),
                remote_addresses: "203.0.113.0/24".into(),
                application: None,
                service: None,
                managed: false,
                builtin_rdp: false,
            },
            allow_foreign_edit: false,
            confirmation: None,
        };
        rig.defense.add_rule(&edit, "ui").unwrap();
        let ours = rig
            .defense
            .rules(&FirewallRulesRequest {
                managed_only: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(ours.rules.len(), 1);
        assert!(ours.rules[0].managed);
        let before = rig
            .defense
            .rules(&FirewallRulesRequest::default())
            .unwrap()
            .total;
        rig.defense
            .block(&block(&["203.0.113.9"], None), "ui")
            .unwrap();
        let purged = rig.defense.purge(&PurgeRequest::default(), "ui").unwrap();
        assert!(purged.removed_rules.len() >= 2);
        let after = rig
            .defense
            .rules(&FirewallRulesRequest::default())
            .unwrap()
            .total;
        assert_eq!(
            after,
            before - 1,
            "only our rule went; everything else stayed"
        );
        assert!(rig.defense.list_blocks().blocks.is_empty());
    }

    #[test]
    fn one_incident_is_blocked_once_even_when_it_escalates() {
        let rig = rig();
        active(&rig);
        let started = alert(7, "203.0.113.9", AlertSeverity::High);
        assert_eq!(rig.defense.on_alert(&started).unwrap().outcome, "blocked");
        let mut escalated = alert(7, "203.0.113.9", AlertSeverity::Critical);
        escalated.phase = AlertPhaseView::Escalated;
        assert!(rig.defense.on_alert(&escalated).is_none());
        let status = rig.defense.status();
        assert_eq!(status.blocks_last_hour, 1);
        assert_eq!(rig.defense.list_blocks().blocks[0].escalation, 1);
        assert_eq!(status.decisions.len(), 1);
    }

    #[test]
    fn an_incident_below_the_threshold_is_acted_on_when_it_escalates() {
        let rig = rig();
        active(&rig);
        let started = alert(8, "203.0.113.9", AlertSeverity::Low);
        assert_eq!(
            rig.defense.on_alert(&started).unwrap().outcome,
            "skipped_below_threshold"
        );
        let mut escalated = alert(8, "203.0.113.9", AlertSeverity::High);
        escalated.phase = AlertPhaseView::Escalated;
        assert_eq!(rig.defense.on_alert(&escalated).unwrap().outcome, "blocked");
    }

    #[test]
    fn rdp_password_guessing_qualifies_from_medium() {
        let rig = rig();
        active(&rig);
        let mut guessing = alert(9, "203.0.113.9", AlertSeverity::Medium);
        guessing.summary_key = "rdp_brute_force".to_owned();
        assert_eq!(rig.defense.on_alert(&guessing).unwrap().outcome, "blocked");
        let other = alert(10, "203.0.113.10", AlertSeverity::Medium);
        assert_eq!(
            rig.defense.on_alert(&other).unwrap().outcome,
            "skipped_below_threshold"
        );
    }

    #[test]
    fn protected_entries_cover_every_source_and_ignore_garbage() {
        let context = NetworkContext {
            gateways: vec!["10.0.0.1".parse().unwrap()],
            dns_servers: vec!["9.9.9.9".parse().unwrap()],
        };
        let entries = protected_entries(
            &context,
            &["198.51.100.1".to_owned(), "garbage".to_owned()],
            &AllowlistConfig {
                allowlist: vec!["192.0.2.0/24".into()],
                management: vec!["203.0.113.0/28".into()],
            },
        );
        let reasons: Vec<&str> = entries.iter().map(|e| e.reason.as_str()).collect();
        for expected in [
            "loopback",
            "gateway",
            "dns",
            "rdp_client",
            "allowlist",
            "management",
        ] {
            assert!(reasons.contains(&expected), "{expected}");
        }
        assert!(protected_set(&entries).contains("203.0.113.5".parse().unwrap()));
        assert!(!protected_set(&entries).contains("203.0.113.99".parse().unwrap()));
    }

    #[test]
    fn the_audit_log_is_read_newest_first_filtered_and_limited() {
        let r = rig();
        for i in 0..5 {
            r.defense
                .audit_entry("operator", "block", &format!("203.0.113.{i}"), "", "ok");
        }
        r.defense
            .audit_entry("agent", "expire", "-", "2 blocks", "ok");
        let (all, truncated) = r.defense.audit_entries(100, None);
        assert_eq!(all.len(), 6);
        assert!(!truncated);
        assert_eq!(all[0].action, "expire", "newest first");
        let (page, truncated) = r.defense.audit_entries(2, None);
        assert_eq!(page.len(), 2);
        assert!(truncated);
        let (found, _) = r.defense.audit_entries(100, Some("203.0.113.3"));
        assert_eq!(found.len(), 1);
        let (found, _) = r.defense.audit_entries(100, Some("EXPIRE"));
        assert_eq!(found.len(), 1, "case-insensitive");
    }
}
