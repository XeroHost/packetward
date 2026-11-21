// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! In-memory [`FirewallBackend`] for tests (here and in the engine). It behaves like Windows where
//! it matters: names are case-insensitive and unique, address lists are stored the way Windows reads
//! them back (`a.b.c.d/255.255.255.255`), and a batch block rule with no/any remote address is
//! rejected because on Windows it would block the whole world.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::addr::windows_readback;
use crate::error::{FirewallError, Result};
use crate::manager::FirewallBackend;
use crate::model::{Action, Direction, Protocol, Rule};

/// One write the fake performed, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeOp {
    Add(String),
    Update(String),
    Remove(String),
    SetEnabled(String, bool),
}

pub struct FakeFirewall {
    rules: Mutex<Vec<Rule>>,
    log: Mutex<Vec<FakeOp>>,
    /// Writes allowed before every further write fails (`usize::MAX` = never fail).
    budget: AtomicUsize,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn normalize(mut rule: Rule) -> Rule {
    rule.remote_addresses = windows_readback(&rule.remote_addresses);
    rule.local_addresses = windows_readback(&rule.local_addresses);
    rule
}

impl Default for FakeFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeFirewall {
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
            budget: AtomicUsize::new(usize::MAX),
        }
    }

    /// A machine that looks like a fresh Windows Server: built-in Remote Desktop rules (enabled), the
    /// shadow rule, and a few unrelated rules.
    pub fn windows_defaults() -> Self {
        let fake = Self::new();
        {
            let mut rules = lock(&fake.rules);
            for (name, proto) in [
                ("Remote Desktop - User Mode (TCP-In)", Protocol::Tcp),
                ("Remote Desktop - User Mode (UDP-In)", Protocol::Udp),
            ] {
                let mut r = Rule::new(name, Direction::Inbound, Action::Allow);
                r.grouping = "Remote Desktop".into();
                r.protocol = proto;
                r.local_ports = "3389".into();
                r.application = Some("%SystemRoot%\\system32\\svchost.exe".into());
                r.service = Some("TermService".into());
                rules.push(r);
            }
            let mut shadow = Rule::new(
                "Remote Desktop - Shadow (TCP-In)",
                Direction::Inbound,
                Action::Allow,
            );
            shadow.grouping = "Remote Desktop".into();
            shadow.protocol = Protocol::Tcp;
            shadow.application = Some("%SystemRoot%\\system32\\RdpSa.exe".into());
            rules.push(shadow);
            let mut smb = Rule::new(
                "File and Printer Sharing (SMB-In)",
                Direction::Inbound,
                Action::Allow,
            );
            smb.grouping = "File and Printer Sharing".into();
            smb.protocol = Protocol::Tcp;
            smb.local_ports = "445".into();
            smb.enabled = false;
            rules.push(smb);
            let mut dns = Rule::new(
                "Core Networking - DNS (UDP-Out)",
                Direction::Outbound,
                Action::Allow,
            );
            dns.grouping = "Core Networking".into();
            dns.protocol = Protocol::Udp;
            dns.remote_ports = "53".into();
            rules.push(dns);
        }
        fake
    }

    /// Adds a rule without any checks (set-up for tests).
    pub fn seed(&self, rule: Rule) {
        lock(&self.rules).push(normalize(rule));
    }

    /// Edits a rule behind the manager's back (simulates a hand edit in wf.msc); not logged.
    pub fn tamper(&self, name: &str, edit: impl FnOnce(&mut Rule)) {
        if let Some(rule) = lock(&self.rules).iter_mut().find(|r| same(&r.name, name)) {
            edit(rule);
        }
    }

    pub fn rules(&self) -> Vec<Rule> {
        lock(&self.rules).clone()
    }

    pub fn rule(&self, name: &str) -> Option<Rule> {
        lock(&self.rules)
            .iter()
            .find(|r| same(&r.name, name))
            .cloned()
    }

    /// Writes performed so far.
    pub fn writes(&self) -> Vec<FakeOp> {
        lock(&self.log).clone()
    }

    pub fn clear_log(&self) {
        lock(&self.log).clear();
    }

    /// Let `n` more writes succeed, then fail every write (simulates a crash half way).
    pub fn fail_writes_after(&self, n: usize) {
        self.budget.store(n, Ordering::SeqCst);
    }

    pub fn heal(&self) {
        self.budget.store(usize::MAX, Ordering::SeqCst);
    }

    fn spend(&self) -> Result<()> {
        let left = self.budget.load(Ordering::SeqCst);
        if left == usize::MAX {
            return Ok(());
        }
        if left == 0 {
            return Err(FirewallError::Backend {
                op: "fake",
                code: 0x8000_4005,
                message: "injected failure".into(),
            });
        }
        self.budget.store(left - 1, Ordering::SeqCst);
        Ok(())
    }

    fn check_write(rule: &Rule) -> Result<()> {
        if rule.name.is_empty() {
            return Err(FirewallError::InvalidRule("empty name".into()));
        }
        if rule.action == Action::Block
            && rule.is_managed()
            && crate::manager::looks_like_batch_name(&rule.name)
            && rule.remote_is_any()
        {
            return Err(FirewallError::InvalidRule(
                "a batch block rule without remote addresses would block everything".into(),
            ));
        }
        Ok(())
    }
}

impl FirewallBackend for FakeFirewall {
    fn list_rules(&self, group: Option<&str>) -> Result<Vec<Rule>> {
        Ok(lock(&self.rules)
            .iter()
            .filter(|r| group.is_none_or(|g| same(&r.grouping, g)))
            .cloned()
            .collect())
    }

    fn get_rule(&self, name: &str) -> Result<Option<Rule>> {
        Ok(self.rule(name))
    }

    fn add_rule(&self, rule: &Rule) -> Result<()> {
        Self::check_write(rule)?;
        let mut rules = lock(&self.rules);
        if rules.iter().any(|r| same(&r.name, &rule.name)) {
            return Err(FirewallError::AlreadyExists(rule.name.clone()));
        }
        self.spend()?;
        rules.push(normalize(rule.clone()));
        lock(&self.log).push(FakeOp::Add(rule.name.clone()));
        Ok(())
    }

    fn update_rule(&self, name: &str, rule: &Rule) -> Result<()> {
        Self::check_write(rule)?;
        let mut rules = lock(&self.rules);
        let slot = rules
            .iter_mut()
            .find(|r| same(&r.name, name))
            .ok_or_else(|| FirewallError::NotFound(name.to_owned()))?;
        self.spend()?;
        *slot = normalize(rule.clone());
        lock(&self.log).push(FakeOp::Update(name.to_owned()));
        Ok(())
    }

    fn remove_rule(&self, name: &str) -> Result<()> {
        let mut rules = lock(&self.rules);
        let pos = rules
            .iter()
            .position(|r| same(&r.name, name))
            .ok_or_else(|| FirewallError::NotFound(name.to_owned()))?;
        self.spend()?;
        rules.remove(pos);
        lock(&self.log).push(FakeOp::Remove(name.to_owned()));
        Ok(())
    }

    fn set_enabled(&self, name: &str, enabled: bool) -> Result<()> {
        let mut rules = lock(&self.rules);
        let rule = rules
            .iter_mut()
            .find(|r| same(&r.name, name))
            .ok_or_else(|| FirewallError::NotFound(name.to_owned()))?;
        self.spend()?;
        rule.enabled = enabled;
        lock(&self.log).push(FakeOp::SetEnabled(name.to_owned(), enabled));
        Ok(())
    }
}
