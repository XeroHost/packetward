// SPDX-License-Identifier: GPL-3.0-or-later
//! The [`Firewall`] trait and the guarded manager that implements it on top of a raw
//! [`FirewallBackend`] (the COM implementation on Windows, an in-memory fake in tests).
//!
//! All safety rules live in the manager, so they apply to every backend:
//! protected-set and breadth screening, foreign-rule protection, lockout confirmations and the
//! ordering of multi-step changes.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pw_core::{Cidr, CidrSet};
use tracing::{info, warn};

use crate::addr::{self, cidr_key, cidr_span, AddrToken};
use crate::error::{FirewallError, Result};
use crate::guard::{
    self, check_block_rule, lockout_class, materially_changes, screen_blocks, BlockOptions,
    Confirmation, LockoutReason, ProtectedSpans, Screened,
};
use crate::model::{
    normalize_profiles, Action, Direction, Protocol, Rule, RuleFilter, PROFILES_ALL,
};
use crate::names::{self, BatchId, GROUP, RDP_ALLOW_TCP, RDP_ALLOW_UDP};
use crate::reconcile::{
    plan_reconcile, split_expired, BatchConfig, DesiredBlock, ExistingBatchRule, ReconcilePlan,
    RuleChange,
};
use crate::shield::{
    FirewallSnapshot, RdpRestrict, RdpRestrictOutcome, RdpState, RestoreReport, RuleState,
    SNAPSHOT_VERSION,
};

/// Raw, unguarded rule storage. Implemented by the COM backend and by [`crate::fake::FakeFirewall`].
/// Nothing outside this crate should call it directly; use [`FirewallManager`].
pub trait FirewallBackend: Send + Sync {
    /// All rules, or only those whose group equals `group` (case-insensitive) when given.
    fn list_rules(&self, group: Option<&str>) -> Result<Vec<Rule>>;
    fn get_rule(&self, name: &str) -> Result<Option<Rule>>;
    /// Fails with `AlreadyExists` when a rule of that name exists.
    fn add_rule(&self, rule: &Rule) -> Result<()>;
    /// Makes the rule called `name` equal to `rule` (properties PacketWard does not model are kept).
    fn update_rule(&self, name: &str, rule: &Rule) -> Result<()>;
    /// Fails with `NotFound` when there is no such rule.
    fn remove_rule(&self, name: &str) -> Result<()>;
    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()>;
}

/// Per-call options for operations on individual rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleOptions<'a> {
    /// The caller has shown the "this is not a PacketWard rule" warning and wants to edit anyway.
    pub allow_foreign_edit: bool,
    /// Typed confirmation for operations that can lock the user out of RDP.
    pub confirmation: Option<&'a Confirmation>,
    /// Required to create or change block rules through the generic rule API.
    pub protected: Option<&'a CidrSet>,
    /// Allow block rules shorter than /8 (IPv4) or /16 (IPv6).
    pub allow_broad: bool,
}

impl<'a> RuleOptions<'a> {
    pub fn foreign_edit(mut self) -> Self {
        self.allow_foreign_edit = true;
        self
    }

    pub fn confirmed(mut self, confirmation: &'a Confirmation) -> Self {
        self.confirmation = Some(confirmation);
        self
    }

    pub fn protecting(mut self, protected: &'a CidrSet) -> Self {
        self.protected = Some(protected);
        self
    }
}

/// What a batch operation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    /// Addresses/ranges blocked by the batch afterwards.
    pub total_blocked: usize,
    /// Rules the batch occupies afterwards.
    pub rules: usize,
    pub added: Vec<Cidr>,
    pub removed: Vec<Cidr>,
    /// Existing blocks dropped because they now overlap the protected set.
    pub evicted_protected: Vec<Cidr>,
    pub skipped_protected: Vec<Cidr>,
    pub skipped_broad: Vec<Cidr>,
    /// `unblock_ips` entries that were not blocked as exact entries.
    pub not_present: Vec<Cidr>,
    /// Entries removed because their expiry passed (`reconcile_blocks`).
    pub expired: Vec<Cidr>,
    /// Rule writes performed (creates + updates + deletes).
    pub rule_writes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub removed: Vec<String>,
}

/// The firewall API the engine and the UI use. Object safe.
pub trait Firewall: Send + Sync {
    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<Rule>>;
    fn get_rule(&self, name: &str) -> Result<Option<Rule>>;
    /// Creates a user rule in the `PacketWard` group (the group and description marker are added).
    fn add_rule(&self, rule: &Rule, opts: &RuleOptions<'_>) -> Result<()>;
    /// Edits a rule in place (renaming is not supported).
    fn update_rule(&self, name: &str, rule: &Rule, opts: &RuleOptions<'_>) -> Result<()>;
    fn remove_rule(&self, name: &str, opts: &RuleOptions<'_>) -> Result<()>;
    fn set_enabled(&self, name: &str, enabled: bool, opts: &RuleOptions<'_>) -> Result<()>;

    /// Adds `ips` to the batch (union with what is already blocked).
    fn block_ips(
        &self,
        batch: &BatchId,
        ips: &[Cidr],
        opts: &BlockOptions<'_>,
    ) -> Result<BatchOutcome>;
    /// Removes exact entries from the batch.
    fn unblock_ips(&self, batch: &BatchId, ips: &[Cidr]) -> Result<BatchOutcome>;
    /// Makes the batch hold exactly `blocks`.
    fn apply_blocklist(
        &self,
        batch: &BatchId,
        blocks: &[Cidr],
        opts: &BlockOptions<'_>,
    ) -> Result<BatchOutcome>;
    /// Like `apply_blocklist`, with expiry: entries whose deadline is `<= now` are dropped.
    fn reconcile_blocks(
        &self,
        batch: &BatchId,
        desired: &[DesiredBlock],
        now: u64,
        opts: &BlockOptions<'_>,
    ) -> Result<BatchOutcome>;
    /// What the batch blocks right now.
    fn list_blocks(&self, batch: &BatchId) -> Result<Vec<Cidr>>;
    /// Deletes every rule of the batch. Idempotent; returns how many rules were removed.
    fn clear_batch(&self, batch: &BatchId) -> Result<usize>;
    /// Removes everything in the `PacketWard` group and nothing else. Idempotent.
    fn purge(&self, opts: &RuleOptions<'_>) -> Result<PurgeReport>;

    // RDP Shield primitives.
    fn rdp_snapshot(&self, now: u64) -> Result<FirewallSnapshot>;
    /// Enables/disables the built-in Remote Desktop rules; returns their previous state.
    fn set_builtin_rdp_enabled(
        &self,
        enabled: bool,
        opts: &RuleOptions<'_>,
    ) -> Result<Vec<RuleState>>;
    /// Creates or updates `PW-RDP-Allow` (and the UDP twin) restricted to `request.allowed`, and
    /// optionally turns the built-in rules off, in that order (never a moment without an allow rule).
    fn rdp_restrict(
        &self,
        request: &RdpRestrict<'_>,
        now: u64,
        opts: &RuleOptions<'_>,
    ) -> Result<RdpRestrictOutcome>;
    /// Puts the RDP state back as recorded. Built-in rules are re-enabled before the allow rules are
    /// removed. Idempotent.
    fn restore_snapshot(&self, snapshot: &FirewallSnapshot) -> Result<RestoreReport>;
}

const DEFAULT_RDP_PORT: u16 = 3389;

/// Guarded implementation of [`Firewall`] over a backend.
pub struct FirewallManager<B: FirewallBackend> {
    backend: B,
    batch: BatchConfig,
    rdp_port: AtomicU16,
    /// One writer at a time for the block batches. Without it two callers (a Guardian block and the
    /// 10-second reconcile) both saw "no rule yet" and both created `PW-AutoBlock-001`: two rules with
    /// one name, of which later updates only ever reached the first, leaving stale blocks behind.
    batch_writes: Mutex<()>,
}

impl<B: FirewallBackend> FirewallManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            batch: BatchConfig::default(),
            rdp_port: AtomicU16::new(DEFAULT_RDP_PORT),
            batch_writes: Mutex::new(()),
        }
    }

    pub fn with_batch_config(mut self, batch: BatchConfig) -> Self {
        self.batch = batch;
        self
    }

    /// The RDP port the lockout guards watch (read from the registry by the caller).
    pub fn set_rdp_port(&self, port: u16) {
        self.rdp_port.store(port, Ordering::Relaxed);
    }

    pub fn rdp_port(&self) -> u16 {
        self.rdp_port.load(Ordering::Relaxed)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn need_confirmation(
        &self,
        opts: &RuleOptions<'_>,
        reason: LockoutReason,
        rule: &str,
    ) -> Result<()> {
        if opts.confirmation.is_some() {
            return Ok(());
        }
        warn!(rule, %reason, "operation refused: typed confirmation required");
        Err(FirewallError::ConfirmationRequired {
            reason,
            rule: rule.to_owned(),
        })
    }

    fn existing_rule(&self, name: &str) -> Result<Rule> {
        self.backend
            .get_rule(name)?
            .ok_or_else(|| FirewallError::NotFound(name.to_owned()))
    }

    fn check_foreign(&self, rule: &Rule, opts: &RuleOptions<'_>) -> Result<()> {
        if !rule.is_managed() && !opts.allow_foreign_edit {
            return Err(FirewallError::ForeignRule(rule.name.clone()));
        }
        Ok(())
    }

    // ---- batches -------------------------------------------------------------------------

    fn writer(&self) -> MutexGuard<'_, ()> {
        self.batch_writes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Rules of one batch that share a name (left by the race described at `batch_writes`, or by an
    /// older agent). The backends address a rule by name, so only the first of them is ever updated or
    /// removed: all copies are deleted here and the normal plan recreates the batch from the desired
    /// set. Returns how many names were repaired.
    fn heal_duplicate_rules(&self, batch: &BatchId) -> Result<usize> {
        let rules = self.backend.list_rules(Some(GROUP))?;
        let mut seen = HashSet::new();
        let mut duplicated = BTreeSet::new();
        for rule in rules
            .iter()
            .filter(|r| batch.parse_index(&r.name).is_some())
        {
            if !seen.insert(rule.name.to_ascii_lowercase()) {
                duplicated.insert(rule.name.clone());
            }
        }
        for name in &duplicated {
            warn!(rule = %name, "several firewall rules share this name: removing the copies and rebuilding the batch");
            // A name can only be removed one copy at a time; the cap stops a misbehaving backend.
            for _ in 0..16 {
                match self.backend.remove_rule(name) {
                    Ok(()) => {}
                    Err(FirewallError::NotFound(_)) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(duplicated.len())
    }

    fn read_batch(&self, batch: &BatchId) -> Result<Vec<ExistingBatchRule>> {
        let rules = self.backend.list_rules(Some(GROUP))?;
        Ok(rules
            .iter()
            .filter_map(|r| batch.parse_index(&r.name).map(|i| existing_from_rule(i, r)))
            .collect())
    }

    fn apply_plan(&self, batch: &BatchId, plan: &ReconcilePlan) -> Result<usize> {
        for change in &plan.changes {
            match change {
                RuleChange::Create { name, addresses } => {
                    let rule = block_rule(batch, name, addresses)?;
                    match self.backend.add_rule(&rule) {
                        // Same name outside the group (or a race): take it over.
                        Err(FirewallError::AlreadyExists(_)) => {
                            self.backend.update_rule(name, &rule)?
                        }
                        other => other?,
                    }
                }
                RuleChange::Update { name, addresses } => {
                    let rule = block_rule(batch, name, addresses)?;
                    self.backend.update_rule(name, &rule)?;
                }
                RuleChange::Delete { name } => match self.backend.remove_rule(name) {
                    Ok(()) | Err(FirewallError::NotFound(_)) => {}
                    Err(e) => return Err(e),
                },
            }
        }
        if !plan.changes.is_empty() {
            info!(%batch, writes = plan.changes.len(), "firewall batch updated");
        }
        Ok(plan.changes.len())
    }

    /// Reads the batch, plans `desired`, applies it and describes the difference.
    fn converge(
        &self,
        batch: &BatchId,
        desired: Vec<Cidr>,
        screened: Screened,
        evicted: Vec<Cidr>,
    ) -> Result<BatchOutcome> {
        self.heal_duplicate_rules(batch)?;
        let existing = self.read_batch(batch)?;
        let current: HashSet<Cidr> = existing
            .iter()
            .flat_map(|r| r.addresses.iter().copied())
            .collect();
        let want: HashSet<Cidr> = desired.iter().copied().collect();
        let plan = plan_reconcile(batch, self.batch, &existing, &desired);
        let writes = self.apply_plan(batch, &plan)?;
        let mut added: Vec<Cidr> = want.difference(&current).copied().collect();
        let mut removed: Vec<Cidr> = current.difference(&want).copied().collect();
        added.sort_by_key(cidr_key);
        removed.sort_by_key(cidr_key);
        let rules_after = existing
            .len()
            .saturating_add(
                plan.changes
                    .iter()
                    .filter(|c| matches!(c, RuleChange::Create { .. }))
                    .count(),
            )
            .saturating_sub(
                plan.changes
                    .iter()
                    .filter(|c| matches!(c, RuleChange::Delete { .. }))
                    .count(),
            );
        Ok(BatchOutcome {
            total_blocked: want.len(),
            rules: rules_after,
            added,
            removed,
            evicted_protected: evicted,
            skipped_protected: screened.skipped_protected,
            skipped_broad: screened.skipped_broad,
            not_present: Vec::new(),
            expired: Vec::new(),
            rule_writes: writes,
        })
    }

    fn current_blocks(&self, batch: &BatchId) -> Result<Vec<Cidr>> {
        let mut all: Vec<Cidr> = self
            .read_batch(batch)?
            .into_iter()
            .flat_map(|r| r.addresses)
            .collect();
        all.sort_by_key(cidr_key);
        all.dedup();
        Ok(all)
    }

    // ---- rule validation -----------------------------------------------------------------

    /// Validates the fields the caller is setting. When editing (`existing` given) only fields that
    /// actually change are checked: built-in rules use keywords (`RPC`, `IPHTTPS`, ...) this crate
    /// does not accept for new input, and `apply_fields` never rewrites an unchanged field.
    fn validate_rule(&self, rule: &Rule, existing: Option<&Rule>) -> Result<()> {
        let bad = |msg: &str| Err(FirewallError::InvalidRule(msg.to_owned()));
        let changed = |f: &dyn Fn(&Rule) -> bool| existing.is_none_or(|e| f(e) != f(rule));
        let same_addr = |a: &str, b: &str| addr::windows_readback(a) == addr::windows_readback(b);
        let ports_changed = changed(&|r| r.local_ports == rule.local_ports)
            || changed(&|r| r.remote_ports == rule.remote_ports);
        if ports_changed
            && (!addr::ports_valid(&rule.local_ports) || !addr::ports_valid(&rule.remote_ports))
        {
            return bad("ports must be * or numbers/ranges between 1 and 65535");
        }
        if (ports_changed || changed(&|r| r.protocol == rule.protocol))
            && !rule.protocol.has_ports()
            && (!addr::ports_any(&rule.local_ports) || !addr::ports_any(&rule.remote_ports))
        {
            return bad("ports can only be set for TCP or UDP rules");
        }
        for (list, old) in [
            (&rule.local_addresses, existing.map(|e| &e.local_addresses)),
            (
                &rule.remote_addresses,
                existing.map(|e| &e.remote_addresses),
            ),
        ] {
            if old.is_some_and(|o| same_addr(o, list)) {
                continue;
            }
            if addr::parse_list(list)
                .iter()
                .any(|t| matches!(t, AddrToken::Invalid(_)))
            {
                return bad("an address entry is not an IP, a CIDR, a range or a known keyword");
            }
            if list.split(',').count() > 10_000 {
                return bad("too many address entries");
            }
        }
        for (new, old) in [
            (&rule.application, existing.map(|e| &e.application)),
            (&rule.service, existing.map(|e| &e.service)),
        ] {
            if old.is_some_and(|o| o == new) {
                continue;
            }
            if let Some(text) = new {
                if text.len() > 260 || text.chars().any(|c| c.is_control() || c == '"') {
                    return bad("application/service contains a character that is not allowed");
                }
            }
        }
        Ok(())
    }

    /// Lockout reasons that apply to the rule as it would be after the write.
    fn check_new_rule(&self, rule: &Rule, opts: &RuleOptions<'_>) -> Result<Option<LockoutReason>> {
        if rule.action != Action::Block {
            return Ok(None);
        }
        let protected = opts.protected.ok_or(FirewallError::ProtectedSetRequired)?;
        check_block_rule(rule, protected, opts.allow_broad, self.rdp_port())
    }
}

fn normalized(mut rule: Rule) -> Rule {
    if rule.remote_addresses.trim().is_empty() {
        rule.remote_addresses = "*".into();
    }
    if rule.local_addresses.trim().is_empty() {
        rule.local_addresses = "*".into();
    }
    rule.application = rule.application.filter(|s| !s.trim().is_empty());
    rule.service = rule.service.filter(|s| !s.trim().is_empty());
    rule
}

/// Name looks like a member of a block batch (`PW-AutoBlock-001`, `PW-List-x-002`, ...).
pub(crate) fn looks_like_batch_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let numbered = lower
        .rsplit_once('-')
        .is_some_and(|(_, n)| n.len() >= 3 && n.bytes().all(|b| b.is_ascii_digit()));
    numbered
        && [
            names::AUTOBLOCK_PREFIX,
            names::MANUAL_PREFIX,
            names::LIST_PREFIX,
        ]
        .iter()
        .any(|p| lower.starts_with(&format!("{}-", p.to_ascii_lowercase())))
}

/// The one shape a batch rule may have. Anything else is rewritten by the next reconcile.
fn is_canonical_block(rule: &Rule) -> bool {
    rule.is_managed()
        && rule.has_marker()
        && rule.enabled
        && rule.direction == Direction::Inbound
        && rule.action == Action::Block
        && rule.protocol == Protocol::Any
        && addr::ports_any(&rule.local_ports)
        && addr::ports_any(&rule.remote_ports)
        && addr::ports_any(&rule.local_addresses)
        && rule.application.is_none()
        && rule.service.is_none()
        && normalize_profiles(rule.profiles) == PROFILES_ALL
}

fn existing_from_rule(index: u32, rule: &Rule) -> ExistingBatchRule {
    let (addresses, junk) = rule.remote_cidrs();
    if junk > 0 {
        warn!(rule = %rule.name, junk, "batch rule contains entries PacketWard does not write; it will be rewritten");
    }
    ExistingBatchRule {
        index,
        name: rule.name.clone(),
        addresses,
        needs_rewrite: junk > 0 || !is_canonical_block(rule),
    }
}

fn block_rule(batch: &BatchId, name: &str, addresses: &[Cidr]) -> Result<Rule> {
    // A block rule without remote addresses blocks the whole world on Windows. Never write one.
    if addresses.is_empty() {
        return Err(FirewallError::InvalidRule(
            "refusing to write a block rule with no addresses".into(),
        ));
    }
    names::validate_rule_name(name, true)?;
    let mut rule = Rule::new(name, Direction::Inbound, Action::Block);
    rule.grouping = GROUP.to_owned();
    rule.description = batch.description();
    rule.remote_addresses = addr::format_cidrs(addresses);
    Ok(rule)
}

/// Equal as far as Windows is concerned (address spelling and description aside).
fn same_rule(a: &Rule, b: &Rule) -> bool {
    a.grouping == b.grouping && a.description == b.description && !materially_changes(a, b)
}

fn shield_rule(name: &str, protocol: Protocol, port: u16, allowed: &[Cidr]) -> Rule {
    let mut rule = Rule::new(name, Direction::Inbound, Action::Allow);
    rule.grouping = GROUP.to_owned();
    rule.description = names::marked_description(&format!(
        "PacketWard RDP Shield: allows RDP only from trusted addresses (port {port})."
    ));
    rule.protocol = protocol;
    rule.local_ports = port.to_string();
    rule.remote_addresses = addr::format_cidrs(allowed);
    rule
}

impl<B: FirewallBackend> Firewall for FirewallManager<B> {
    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<Rule>> {
        let all = self.backend.list_rules(filter.group.as_deref())?;
        Ok(all.into_iter().filter(|r| filter.matches(r)).collect())
    }

    fn get_rule(&self, name: &str) -> Result<Option<Rule>> {
        self.backend.get_rule(name)
    }

    fn add_rule(&self, rule: &Rule, opts: &RuleOptions<'_>) -> Result<()> {
        names::validate_rule_name(&rule.name, false)?;
        self.validate_rule(rule, None)?;
        let mut rule = normalized(rule.clone());
        if let Some(reason) = self.check_new_rule(&rule, opts)? {
            self.need_confirmation(opts, reason, &rule.name)?;
        }
        if self.backend.get_rule(&rule.name)?.is_some() {
            return Err(FirewallError::AlreadyExists(rule.name));
        }
        rule.grouping = GROUP.to_owned();
        rule.description = names::marked_description(&rule.description);
        self.backend.add_rule(&rule)?;
        info!(rule = %rule.name, "firewall rule created");
        Ok(())
    }

    fn update_rule(&self, name: &str, rule: &Rule, opts: &RuleOptions<'_>) -> Result<()> {
        let existing = self.existing_rule(name)?;
        self.check_foreign(&existing, opts)?;
        if looks_like_batch_name(name) && existing.is_managed() {
            return Err(FirewallError::BatchManaged(name.to_owned()));
        }
        if rule.name != name {
            return Err(FirewallError::InvalidRule(
                "renaming a rule is not supported".into(),
            ));
        }
        self.validate_rule(rule, Some(&existing))?;
        let mut new = normalized(rule.clone());
        if existing.is_managed() {
            new.grouping = GROUP.to_owned();
            new.description = names::marked_description(&new.description);
        } else {
            new.grouping = existing.grouping.clone();
        }
        if new.action == Action::Block
            && (existing.action != Action::Block
                || addr::windows_readback(&existing.remote_addresses)
                    != addr::windows_readback(&new.remote_addresses))
        {
            if let Some(reason) = self.check_new_rule(&new, opts)? {
                self.need_confirmation(opts, reason, name)?;
            }
        } else if guard::blocks_rdp_for_everyone(&new, self.rdp_port())
            && !guard::blocks_rdp_for_everyone(&existing, self.rdp_port())
        {
            self.need_confirmation(
                opts,
                LockoutReason::BlocksRdp {
                    port: self.rdp_port(),
                },
                name,
            )?;
        }
        if let Some(reason) = lockout_class(&existing, self.rdp_port()) {
            if materially_changes(&existing, &new) {
                self.need_confirmation(opts, reason, name)?;
            }
        }
        self.backend.update_rule(name, &new)?;
        info!(rule = name, "firewall rule updated");
        Ok(())
    }

    fn remove_rule(&self, name: &str, opts: &RuleOptions<'_>) -> Result<()> {
        let existing = self.existing_rule(name)?;
        self.check_foreign(&existing, opts)?;
        if let Some(reason) = lockout_class(&existing, self.rdp_port()) {
            self.need_confirmation(opts, reason, name)?;
        }
        self.backend.remove_rule(name)?;
        info!(rule = name, "firewall rule removed");
        Ok(())
    }

    fn set_enabled(&self, name: &str, enabled: bool, opts: &RuleOptions<'_>) -> Result<()> {
        let existing = self.existing_rule(name)?;
        self.check_foreign(&existing, opts)?;
        if existing.enabled == enabled {
            return Ok(());
        }
        if !enabled {
            if let Some(reason) = lockout_class(&existing, self.rdp_port()) {
                self.need_confirmation(opts, reason, name)?;
            }
        } else {
            let mut after = existing.clone();
            after.enabled = true;
            if guard::blocks_rdp_for_everyone(&after, self.rdp_port()) {
                self.need_confirmation(
                    opts,
                    LockoutReason::BlocksRdp {
                        port: self.rdp_port(),
                    },
                    name,
                )?;
            }
        }
        self.backend.set_enabled(name, enabled)?;
        info!(rule = name, enabled, "firewall rule enabled state changed");
        Ok(())
    }

    fn block_ips(
        &self,
        batch: &BatchId,
        ips: &[Cidr],
        opts: &BlockOptions<'_>,
    ) -> Result<BatchOutcome> {
        // Screen first: a refused batch performs no write and no read.
        let screened = screen_blocks(ips, opts)?;
        let _writer = self.writer();
        let spans = ProtectedSpans::new(opts.protected);
        let mut desired = Vec::new();
        let mut evicted = Vec::new();
        for block in self.current_blocks(batch)? {
            if spans.overlaps(&cidr_span(&block)) {
                evicted.push(block);
            } else {
                desired.push(block);
            }
        }
        desired.extend(screened.accepted.iter().copied());
        self.converge(batch, desired, screened, evicted)
    }

    fn unblock_ips(&self, batch: &BatchId, ips: &[Cidr]) -> Result<BatchOutcome> {
        let _writer = self.writer();
        let current = self.current_blocks(batch)?;
        let drop: HashSet<Cidr> = ips.iter().copied().collect();
        let held: HashSet<Cidr> = current.iter().copied().collect();
        let mut not_present: Vec<Cidr> = drop.difference(&held).copied().collect();
        not_present.sort_by_key(cidr_key);
        let desired: Vec<Cidr> = current.into_iter().filter(|c| !drop.contains(c)).collect();
        let mut outcome = self.converge(batch, desired, Screened::default(), Vec::new())?;
        outcome.not_present = not_present;
        Ok(outcome)
    }

    fn apply_blocklist(
        &self,
        batch: &BatchId,
        blocks: &[Cidr],
        opts: &BlockOptions<'_>,
    ) -> Result<BatchOutcome> {
        let screened = screen_blocks(blocks, opts)?;
        let _writer = self.writer();
        let desired = screened.accepted.clone();
        self.converge(batch, desired, screened, Vec::new())
    }

    fn reconcile_blocks(
        &self,
        batch: &BatchId,
        desired: &[DesiredBlock],
        now: u64,
        opts: &BlockOptions<'_>,
    ) -> Result<BatchOutcome> {
        let (active, expired) = split_expired(desired, now);
        let screened = screen_blocks(&active, opts)?;
        let _writer = self.writer();
        let accepted = screened.accepted.clone();
        let mut outcome = self.converge(batch, accepted, screened, Vec::new())?;
        outcome.expired = expired;
        Ok(outcome)
    }

    fn list_blocks(&self, batch: &BatchId) -> Result<Vec<Cidr>> {
        self.current_blocks(batch)
    }

    fn clear_batch(&self, batch: &BatchId) -> Result<usize> {
        let _writer = self.writer();
        let mut removed = 0;
        for rule in self.read_batch(batch)? {
            match self.backend.remove_rule(&rule.name) {
                Ok(()) => removed += 1,
                Err(FirewallError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(removed)
    }

    fn purge(&self, opts: &RuleOptions<'_>) -> Result<PurgeReport> {
        let _writer = self.writer();
        let rules = self.backend.list_rules(Some(GROUP))?;
        // Only exact members of the group; the backend filter is advisory.
        let mine: Vec<&Rule> = rules.iter().filter(|r| r.grouping == GROUP).collect();
        for rule in &mine {
            if let Some(reason) = lockout_class(rule, self.rdp_port()) {
                self.need_confirmation(opts, reason, &rule.name)?;
            }
        }
        let mut report = PurgeReport::default();
        // Block rules first, allow rules (RDP shield) last, so a failure half way leaves access open.
        let mut ordered = mine;
        ordered.sort_by_key(|r| r.action == Action::Allow);
        for rule in ordered {
            match self.backend.remove_rule(&rule.name) {
                Ok(()) => report.removed.push(rule.name.clone()),
                Err(FirewallError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        info!(
            removed = report.removed.len(),
            "PacketWard firewall rules purged"
        );
        Ok(report)
    }

    fn rdp_snapshot(&self, now: u64) -> Result<FirewallSnapshot> {
        let rules = self.backend.list_rules(None)?;
        let mut builtin: Vec<RuleState> = rules
            .iter()
            .filter(|r| guard::is_builtin_rdp_rule(r))
            .map(|r| RuleState {
                name: r.name.clone(),
                enabled: r.enabled,
            })
            .collect();
        builtin.sort_by(|a, b| a.name.cmp(&b.name));
        let mut shield: Vec<Rule> = rules
            .into_iter()
            .filter(|r| {
                r.is_managed()
                    && (r.name.eq_ignore_ascii_case(RDP_ALLOW_TCP)
                        || r.name.eq_ignore_ascii_case(RDP_ALLOW_UDP))
            })
            .collect();
        shield.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(FirewallSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: now,
            rdp: RdpState {
                port: self.rdp_port(),
                builtin,
                shield,
            },
        })
    }

    fn set_builtin_rdp_enabled(
        &self,
        enabled: bool,
        opts: &RuleOptions<'_>,
    ) -> Result<Vec<RuleState>> {
        let rules = self.backend.list_rules(None)?;
        let targets: Vec<&Rule> = rules
            .iter()
            .filter(|r| guard::is_builtin_rdp_rule(r))
            .collect();
        if !enabled && targets.iter().any(|r| r.enabled) {
            self.need_confirmation(opts, LockoutReason::BuiltinRdpRule, "Remote Desktop")?;
        }
        let previous = targets
            .iter()
            .map(|r| RuleState {
                name: r.name.clone(),
                enabled: r.enabled,
            })
            .collect();
        for rule in targets {
            if rule.enabled != enabled {
                self.backend.set_enabled(&rule.name, enabled)?;
            }
        }
        Ok(previous)
    }

    fn rdp_restrict(
        &self,
        request: &RdpRestrict<'_>,
        now: u64,
        opts: &RuleOptions<'_>,
    ) -> Result<RdpRestrictOutcome> {
        if request.port == 0 {
            return Err(FirewallError::InvalidRule("RDP port must not be 0".into()));
        }
        if request.allowed.is_empty() {
            return Err(FirewallError::EmptyAllowList);
        }
        if request.allowed.len() > self.batch.max_per_rule {
            return Err(FirewallError::InvalidRule(
                "too many addresses in the RDP allow list".into(),
            ));
        }
        let spans: Vec<_> = request.allowed.iter().map(cidr_span).collect();
        let excluded: Vec<IpAddr> = request
            .required_clients
            .iter()
            .copied()
            .filter(|ip| !spans.iter().any(|s| s.contains_addr(*ip)))
            .collect();
        if !excluded.is_empty() {
            return Err(FirewallError::RdpClientExcluded(excluded));
        }
        if request.disable_builtin && request.required_clients.is_empty() {
            // Nobody to protect means nobody the guard above could check: do not guess.
            return Err(FirewallError::NoTrustedClients);
        }
        if request.disable_builtin {
            self.need_confirmation(opts, LockoutReason::RestrictRdp, RDP_ALLOW_TCP)?;
        }
        let snapshot = self.rdp_snapshot(now)?;

        // 1. The allow rules first, so there is never a moment without one.
        let mut wanted = vec![shield_rule(
            RDP_ALLOW_TCP,
            Protocol::Tcp,
            request.port,
            request.allowed,
        )];
        if request.include_udp {
            wanted.push(shield_rule(
                RDP_ALLOW_UDP,
                Protocol::Udp,
                request.port,
                request.allowed,
            ));
        }
        let mut touched = Vec::new();
        for rule in &wanted {
            self.upsert_internal(rule)?;
            touched.push(rule.name.clone());
        }
        if !request.include_udp && snapshot.rdp.shield.iter().any(|r| r.name == RDP_ALLOW_UDP) {
            // A previous run opened UDP; the new request does not want it.
            self.remove_internal(RDP_ALLOW_UDP)?;
        }
        // 2. Then the built-in rules off.
        let mut disabled = Vec::new();
        if request.disable_builtin {
            for state in &snapshot.rdp.builtin {
                if state.enabled {
                    self.backend.set_enabled(&state.name, false)?;
                    disabled.push(state.name.clone());
                }
            }
        }
        info!(
            port = request.port,
            allowed = request.allowed.len(),
            disabled = disabled.len(),
            "RDP restricted"
        );
        Ok(RdpRestrictOutcome {
            snapshot,
            created_or_updated: touched,
            disabled,
        })
    }

    fn restore_snapshot(&self, snapshot: &FirewallSnapshot) -> Result<RestoreReport> {
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(FirewallError::InvalidRule(format!(
                "unsupported snapshot version {}",
                snapshot.version
            )));
        }
        let mut report = RestoreReport::default();
        // 1. Re-enable first (this only ever widens access), then disable what was disabled.
        let mut ordered: Vec<&RuleState> = snapshot.rdp.builtin.iter().collect();
        ordered.sort_by_key(|s| !s.enabled);
        for state in ordered {
            match self.backend.get_rule(&state.name)? {
                None => report.missing.push(state.name.clone()),
                Some(rule) if rule.enabled != state.enabled => {
                    self.backend.set_enabled(&state.name, state.enabled)?;
                    if state.enabled {
                        report.reenabled.push(state.name.clone());
                    } else {
                        report.redisabled.push(state.name.clone());
                    }
                }
                Some(_) => {}
            }
        }
        // 2. Allow rules: put back what existed, remove what did not.
        for rule in &snapshot.rdp.shield {
            if self.upsert_if_different(rule)? {
                report.shield_restored.push(rule.name.clone());
            }
        }
        for name in [RDP_ALLOW_TCP, RDP_ALLOW_UDP] {
            let wanted = snapshot
                .rdp
                .shield
                .iter()
                .any(|r| r.name.eq_ignore_ascii_case(name));
            if !wanted && self.remove_internal(name)? {
                report.shield_removed.push(name.to_owned());
            }
        }
        info!(?report, "RDP firewall state restored");
        Ok(report)
    }
}

impl<B: FirewallBackend> FirewallManager<B> {
    /// Create or overwrite one of PacketWard's own rules (no foreign/lockout checks: these are the
    /// shield's rules and the caller already passed the guards).
    fn upsert_internal(&self, rule: &Rule) -> Result<()> {
        match self.backend.get_rule(&rule.name)? {
            Some(_) => self.backend.update_rule(&rule.name, rule),
            None => self.backend.add_rule(rule),
        }
    }

    fn upsert_if_different(&self, rule: &Rule) -> Result<bool> {
        match self.backend.get_rule(&rule.name)? {
            Some(current) if same_rule(&current, rule) => Ok(false),
            Some(_) => self.backend.update_rule(&rule.name, rule).map(|()| true),
            None => self.backend.add_rule(rule).map(|()| true),
        }
    }

    fn remove_internal(&self, name: &str) -> Result<bool> {
        match self.backend.get_rule(name)? {
            Some(rule) if rule.is_managed() => match self.backend.remove_rule(name) {
                Ok(()) => Ok(true),
                Err(FirewallError::NotFound(_)) => Ok(false),
                Err(e) => Err(e),
            },
            _ => Ok(false),
        }
    }
}
