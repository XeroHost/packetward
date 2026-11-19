// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure planning of block batches: which rules to create, rewrite or delete so that the batch
//! holds exactly the desired addresses, touching as few rules as possible.
//!
//! Rules are *sticky*: an address stays in the rule it is in; new addresses fill the free room of
//! existing rules before a new rule is started; a rule that ends up empty is deleted (a block rule
//! with no addresses means "block everyone" on Windows, so it must never exist). Small rules are
//! merged when two of them fit in one. Creates and updates are listed before deletes so an address
//! that moves between rules is never unblocked in between.

use std::collections::{BTreeMap, HashSet};

use pw_core::Cidr;

use crate::addr::cidr_key;
use crate::names::BatchId;

/// Default addresses per rule.
pub const DEFAULT_MAX_PER_RULE: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchConfig {
    /// Maximum remote addresses/ranges in one rule (at least 1).
    pub max_per_rule: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_per_rule: DEFAULT_MAX_PER_RULE,
        }
    }
}

impl BatchConfig {
    pub fn new(max_per_rule: usize) -> Self {
        Self {
            max_per_rule: max_per_rule.max(1),
        }
    }
}

/// A block rule that already exists, as read back from the firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingBatchRule {
    pub index: u32,
    pub name: String,
    pub addresses: Vec<Cidr>,
    /// The rule is wrong in some way other than its addresses (disabled, not a block, junk entries,
    /// wrong group...) and must be rewritten even if its address set is already right.
    pub needs_rewrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleChange {
    Create { name: String, addresses: Vec<Cidr> },
    Update { name: String, addresses: Vec<Cidr> },
    Delete { name: String },
}

impl RuleChange {
    pub fn name(&self) -> &str {
        match self {
            Self::Create { name, .. } | Self::Update { name, .. } | Self::Delete { name } => name,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub changes: Vec<RuleChange>,
}

impl ReconcilePlan {
    pub fn is_noop(&self) -> bool {
        self.changes.is_empty()
    }
}

/// One desired block with an optional expiry (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesiredBlock {
    pub block: Cidr,
    pub expires_at: Option<u64>,
}

/// Splits desired blocks into the ones still active at `now` and the ones that expired (an entry
/// expiring exactly at `now` is expired). Duplicates keep the latest expiry.
pub fn split_expired(desired: &[DesiredBlock], now: u64) -> (Vec<Cidr>, Vec<Cidr>) {
    let mut latest: BTreeMap<(bool, u128, u8), (Cidr, Option<u64>)> = BTreeMap::new();
    for d in desired {
        let entry = latest
            .entry(cidr_key(&d.block))
            .or_insert((d.block, d.expires_at));
        // `None` = never expires, which beats any deadline.
        entry.1 = match (entry.1, d.expires_at) {
            (None, _) | (_, None) => None,
            (Some(a), Some(b)) => Some(a.max(b)),
        };
    }
    let mut active = Vec::new();
    let mut expired = Vec::new();
    for (block, expiry) in latest.into_values() {
        match expiry {
            Some(t) if t <= now => expired.push(block),
            _ => active.push(block),
        }
    }
    (active, expired)
}

struct Slot {
    index: u32,
    name: String,
    existed: bool,
    needs_rewrite: bool,
    original: HashSet<Cidr>,
    current: Vec<Cidr>,
}

/// Plans the changes that make the batch contain exactly `desired`.
///
/// Deterministic: the same inputs always give the same plan.
pub fn plan_reconcile(
    batch: &BatchId,
    config: BatchConfig,
    existing: &[ExistingBatchRule],
    desired: &[Cidr],
) -> ReconcilePlan {
    let cap = config.max_per_rule.max(1);
    let desired_set: HashSet<Cidr> = desired.iter().copied().collect();

    // 1. Keep what is still wanted, where it already is.
    let mut slots: BTreeMap<u32, Slot> = BTreeMap::new();
    let mut placed: HashSet<Cidr> = HashSet::new();
    let mut ordered: Vec<&ExistingBatchRule> = existing.iter().collect();
    ordered.sort_by_key(|r| r.index);
    for rule in ordered {
        if slots.contains_key(&rule.index) {
            // Two rules with the same index: the second is a stray copy; it is removed by name below.
            continue;
        }
        let mut kept = Vec::new();
        for addr in &rule.addresses {
            // Over capacity, unwanted, or already kept by another rule: not kept here.
            if kept.len() < cap && desired_set.contains(addr) && placed.insert(*addr) {
                kept.push(*addr);
            }
        }
        slots.insert(
            rule.index,
            Slot {
                index: rule.index,
                name: rule.name.clone(),
                existed: true,
                needs_rewrite: rule.needs_rewrite,
                original: rule.addresses.iter().copied().collect(),
                current: kept,
            },
        );
    }

    // 2. New addresses fill the free room of existing rules (lowest index first), then new rules.
    let mut fresh: Vec<Cidr> = desired_set.difference(&placed).copied().collect();
    fresh.sort_by_key(cidr_key);
    let mut fresh = fresh.into_iter().peekable();
    for slot in slots.values_mut() {
        while slot.current.len() < cap {
            match fresh.next() {
                Some(a) => slot.current.push(a),
                None => break,
            }
        }
    }
    let mut next_index = 1u32;
    while fresh.peek().is_some() {
        while slots.contains_key(&next_index) {
            next_index += 1;
        }
        let mut current = Vec::new();
        while current.len() < cap {
            match fresh.next() {
                Some(a) => current.push(a),
                None => break,
            }
        }
        slots.insert(
            next_index,
            Slot {
                index: next_index,
                name: batch.rule_name(next_index),
                existed: false,
                needs_rewrite: false,
                original: HashSet::new(),
                current,
            },
        );
    }

    // 3. Merge small rules: while two rules fit into one, fold the smallest into the fullest fit.
    loop {
        let mut live: Vec<u32> = slots
            .values()
            .filter(|s| !s.current.is_empty())
            .map(|s| s.index)
            .collect();
        live.sort_by_key(|i| (slots[i].current.len(), *i));
        let mut merged = false;
        for &small in &live {
            let small_len = slots[&small].current.len();
            let target = live
                .iter()
                .copied()
                .filter(|&i| i != small && slots[&i].current.len() + small_len <= cap)
                .max_by_key(|&i| (slots[&i].current.len(), std::cmp::Reverse(i)));
            if let Some(target) = target {
                let moved = slots
                    .get_mut(&small)
                    .map(|s| std::mem::take(&mut s.current))
                    .unwrap_or_default();
                if let Some(t) = slots.get_mut(&target) {
                    t.current.extend(moved);
                }
                merged = true;
                break;
            }
        }
        if !merged {
            break;
        }
    }

    // 4. Emit: creates, then updates, then deletes.
    let mut creates = Vec::new();
    let mut updates = Vec::new();
    let mut deletes = Vec::new();
    for slot in slots.values_mut() {
        slot.current.sort_by_key(cidr_key);
        let now: HashSet<Cidr> = slot.current.iter().copied().collect();
        if slot.current.is_empty() {
            if slot.existed {
                deletes.push(RuleChange::Delete {
                    name: slot.name.clone(),
                });
            }
        } else if !slot.existed {
            creates.push(RuleChange::Create {
                name: slot.name.clone(),
                addresses: slot.current.clone(),
            });
        } else if slot.needs_rewrite || now != slot.original {
            updates.push(RuleChange::Update {
                name: slot.name.clone(),
                addresses: slot.current.clone(),
            });
        }
    }
    // Stray duplicates (same index twice) are deleted by name.
    let mut seen_names: HashSet<&str> = slots.values().map(|s| s.name.as_str()).collect();
    for rule in existing {
        if seen_names.insert(rule.name.as_str()) {
            deletes.push(RuleChange::Delete {
                name: rule.name.clone(),
            });
        }
    }
    let mut changes = creates;
    changes.extend(updates);
    changes.extend(deletes);
    ReconcilePlan { changes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn host(n: u32) -> Cidr {
        // 10.0.0.0/8 hosts: 16.7 M addresses, plenty for tests.
        Cidr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n)), 32).unwrap()
    }

    fn hosts(range: std::ops::Range<u32>) -> Vec<Cidr> {
        range.map(host).collect()
    }

    /// Applies a plan to an in-memory model of the existing rules.
    fn apply(existing: &mut Vec<ExistingBatchRule>, plan: &ReconcilePlan, batch: &BatchId) {
        for change in &plan.changes {
            match change {
                RuleChange::Create { name, addresses } => {
                    existing.push(ExistingBatchRule {
                        index: batch.parse_index(name).unwrap(),
                        name: name.clone(),
                        addresses: addresses.clone(),
                        needs_rewrite: false,
                    });
                }
                RuleChange::Update { name, addresses } => {
                    let r = existing.iter_mut().find(|r| &r.name == name).unwrap();
                    r.addresses = addresses.clone();
                    r.needs_rewrite = false;
                }
                RuleChange::Delete { name } => existing.retain(|r| &r.name != name),
            }
        }
    }

    fn converge(
        existing: &mut Vec<ExistingBatchRule>,
        batch: &BatchId,
        cfg: BatchConfig,
        desired: &[Cidr],
    ) {
        let plan = plan_reconcile(batch, cfg, existing, desired);
        apply(existing, &plan, batch);
    }

    fn state_set(existing: &[ExistingBatchRule]) -> HashSet<Cidr> {
        existing
            .iter()
            .flat_map(|r| r.addresses.iter().copied())
            .collect()
    }

    #[test]
    fn five_thousand_ips_use_five_rules() {
        let batch = BatchId::auto_block();
        let plan = plan_reconcile(&batch, BatchConfig::default(), &[], &hosts(0..5000));
        assert_eq!(plan.changes.len(), 5);
        assert!(plan
            .changes
            .iter()
            .all(|c| matches!(c, RuleChange::Create { addresses, .. } if addresses.len() == 1000)));
        let names: Vec<_> = plan.changes.iter().map(|c| c.name().to_owned()).collect();
        assert_eq!(names[0], "PW-AutoBlock-001");
        assert_eq!(names[4], "PW-AutoBlock-005");
    }

    #[test]
    fn a_single_ip_makes_a_single_rule_and_nothing_makes_none() {
        let batch = BatchId::auto_block();
        assert_eq!(
            plan_reconcile(&batch, BatchConfig::default(), &[], &hosts(0..1))
                .changes
                .len(),
            1
        );
        assert!(plan_reconcile(&batch, BatchConfig::default(), &[], &[]).is_noop());
    }

    #[test]
    fn an_unchanged_set_is_a_noop() {
        let batch = BatchId::auto_block();
        let mut state = Vec::new();
        let want = hosts(0..2500);
        let plan = plan_reconcile(&batch, BatchConfig::default(), &state, &want);
        apply(&mut state, &plan, &batch);
        assert!(plan_reconcile(&batch, BatchConfig::default(), &state, &want).is_noop());
        // Order of the desired list does not matter.
        let mut shuffled = want.clone();
        shuffled.reverse();
        assert!(plan_reconcile(&batch, BatchConfig::default(), &state, &shuffled).is_noop());
    }

    #[test]
    fn removing_one_ip_rewrites_only_its_rule() {
        let batch = BatchId::auto_block();
        let mut state = Vec::new();
        let mut want = hosts(0..5000);
        converge(&mut state, &batch, BatchConfig::default(), &want);
        want.retain(|c| *c != host(2500)); // lives in rule 3
        let plan = plan_reconcile(&batch, BatchConfig::default(), &state, &want);
        assert_eq!(plan.changes.len(), 1);
        match &plan.changes[0] {
            RuleChange::Update { name, addresses } => {
                assert_eq!(name, "PW-AutoBlock-003");
                assert_eq!(addresses.len(), 999);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn adding_ips_fills_free_room_before_creating_rules() {
        let batch = BatchId::auto_block();
        let mut state = Vec::new();
        converge(&mut state, &batch, BatchConfig::default(), &hosts(0..1500));
        // Room: 500 in rule 2. Add 400: only rule 2 changes.
        let plan = plan_reconcile(&batch, BatchConfig::default(), &state, &hosts(0..1900));
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].name(), "PW-AutoBlock-002");
        // Add 600 more than room: rule 2 fills and rule 3 is created, rule 1 untouched.
        let plan = plan_reconcile(&batch, BatchConfig::default(), &state, &hosts(0..2100));
        let names: Vec<_> = plan.changes.iter().map(RuleChange::name).collect();
        assert_eq!(names, ["PW-AutoBlock-003", "PW-AutoBlock-002"]);
    }

    #[test]
    fn an_emptied_rule_is_deleted_never_left_empty() {
        let batch = BatchId::auto_block();
        let mut state = Vec::new();
        converge(&mut state, &batch, BatchConfig::new(2), &hosts(0..4));
        // Rule 1 = {0,1}, rule 2 = {2,3}. Drop 0 and 1.
        let plan = plan_reconcile(&batch, BatchConfig::new(2), &state, &hosts(2..4));
        assert_eq!(
            plan.changes,
            vec![RuleChange::Delete {
                name: "PW-AutoBlock-001".into()
            }]
        );
        apply(&mut state, &plan, &batch);
        // Everything gone: both rules removed, none updated to empty.
        let plan = plan_reconcile(&batch, BatchConfig::new(2), &state, &[]);
        assert!(plan
            .changes
            .iter()
            .all(|c| matches!(c, RuleChange::Delete { .. })));
        apply(&mut state, &plan, &batch);
        assert!(state.is_empty());
        // Idempotent.
        assert!(plan_reconcile(&batch, BatchConfig::new(2), &state, &[]).is_noop());
    }

    #[test]
    fn small_rules_are_merged_and_creates_come_before_deletes() {
        let batch = BatchId::auto_block();
        let mut state = Vec::new();
        converge(&mut state, &batch, BatchConfig::new(10), &hosts(0..30));
        // Keep 3 addresses from each rule: 9 addresses should collapse into one rule.
        let want: Vec<Cidr> = [0, 1, 2, 10, 11, 12, 20, 21, 22].map(host).to_vec();
        let plan = plan_reconcile(&batch, BatchConfig::new(10), &state, &want);
        let kinds: Vec<&str> = plan
            .changes
            .iter()
            .map(|c| match c {
                RuleChange::Create { .. } => "create",
                RuleChange::Update { .. } => "update",
                RuleChange::Delete { .. } => "delete",
            })
            .collect();
        let first_delete = kinds.iter().position(|k| *k == "delete").unwrap();
        assert!(kinds[..first_delete].iter().all(|k| *k != "delete"));
        assert!(kinds[first_delete..].iter().all(|k| *k == "delete"));
        apply(&mut state, &plan, &batch);
        assert_eq!(state.len(), 1);
        assert_eq!(state_set(&state).len(), 9);
    }

    #[test]
    fn a_rule_that_is_wrong_in_other_ways_is_rewritten() {
        let batch = BatchId::auto_block();
        let existing = vec![ExistingBatchRule {
            index: 1,
            name: batch.rule_name(1),
            addresses: hosts(0..3),
            needs_rewrite: true,
        }];
        let plan = plan_reconcile(&batch, BatchConfig::default(), &existing, &hosts(0..3));
        assert_eq!(plan.changes.len(), 1);
        assert!(matches!(plan.changes[0], RuleChange::Update { .. }));
    }

    #[test]
    fn stray_duplicate_names_are_removed() {
        let batch = BatchId::auto_block();
        let dup = |addrs| ExistingBatchRule {
            index: 1,
            name: batch.rule_name(1),
            addresses: addrs,
            needs_rewrite: false,
        };
        let mut other = dup(hosts(5..6));
        other.name = "PW-AutoBlock-001 ".into(); // a differently spelled stray with the same index
        let plan = plan_reconcile(
            &batch,
            BatchConfig::default(),
            &[dup(hosts(0..3)), other],
            &hosts(0..3),
        );
        assert_eq!(
            plan.changes,
            vec![RuleChange::Delete {
                name: "PW-AutoBlock-001 ".into()
            }]
        );
    }

    #[test]
    fn expiry_split() {
        let d = |n, e| DesiredBlock {
            block: host(n),
            expires_at: e,
        };
        let (active, expired) = split_expired(
            &[
                d(1, Some(100)),
                d(2, Some(50)),
                d(3, None),
                d(4, Some(100)),
                d(4, Some(10)),
                d(5, Some(60)),
                d(5, None),
            ],
            60,
        );
        assert_eq!(active, vec![host(1), host(3), host(4), host(5)]);
        assert_eq!(expired, vec![host(2)]);
    }

    /// Tiny deterministic generator so the property tests need no extra dependency.
    struct Rng(u64);
    impl Rng {
        fn step(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.step() % n
        }
    }

    #[test]
    fn random_churn_keeps_the_invariants() {
        for seed in 1..=40u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let cap = 1 + rng.below(12) as usize;
            let cfg = BatchConfig::new(cap);
            let batch = BatchId::auto_block();
            let mut state: Vec<ExistingBatchRule> = Vec::new();
            for _round in 0..30 {
                let n = rng.below(80) as u32;
                let offset = rng.below(60) as u32;
                let want = hosts(offset..offset + n);
                let plan = plan_reconcile(&batch, cfg, &state, &want);
                let before = state.clone();
                apply(&mut state, &plan, &batch);
                // Exactly the desired set, no duplicates across rules.
                let total: usize = state.iter().map(|r| r.addresses.len()).sum();
                assert_eq!(total, want.len(), "seed {seed}");
                assert_eq!(
                    state_set(&state),
                    want.iter().copied().collect::<HashSet<_>>()
                );
                // Capacity and non-empty.
                assert!(state
                    .iter()
                    .all(|r| !r.addresses.is_empty() && r.addresses.len() <= cap));
                // Compact: any two rules together exceed the cap.
                for (i, a) in state.iter().enumerate() {
                    for b in &state[i + 1..] {
                        assert!(a.addresses.len() + b.addresses.len() > cap, "seed {seed}");
                    }
                }
                // Re-planning is a no-op (converged).
                assert!(plan_reconcile(&batch, cfg, &state, &want).is_noop());
                // Minimal-ish: untouched rules are byte-for-byte the same.
                let touched: HashSet<&str> = plan.changes.iter().map(RuleChange::name).collect();
                for old in &before {
                    if !touched.contains(old.name.as_str()) {
                        assert!(state.iter().any(|r| r == old));
                    }
                }
            }
        }
    }
}
