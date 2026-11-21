// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! RDP Shield (M7b): the exposure audit and the guarded changes to Remote Desktop.
//!
//! Every change is a **transaction**: the previous state is saved (to disk, so it survives an agent
//! restart), the change is applied, and a confirmation timer starts. If nobody confirms from a new
//! connection before the deadline, **the agent itself puts everything back** (the UI may be unreachable
//! precisely because the change cut the connection). Addresses with a successful RDP logon are always in
//! the allow list of a restriction. `reset` restores RDP to factory state.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use pw_core::Cidr;
use pw_firewall::addr::format_cidr;
use pw_firewall::{
    Confirmation, Firewall, FirewallError, FirewallSnapshot, RdpRestrict, RuleFilter, RuleOptions,
    CONFIRMATION_PHRASE,
};
use pw_netstat::rdp_control::{Lockout, RdpConfig, RdpControl, DEFAULT_PORT};
use pw_proto::{
    AlertSeverity, ErrorCode, ErrorPayload, LogonAudit, RdpAttempts, RdpAudit,
    RdpEndSessionRequest, RdpFinding, RdpLockoutRequest, RdpPending, RdpPortRequest,
    RdpRestrictRequest,
};
use serde::{Deserialize, Serialize};

use crate::defense::Defense;
use crate::trust::TrustState;

/// Seconds the user has to confirm a change from a new connection.
pub const DEFAULT_CONFIRM_SECS: u32 = 120;
/// A revert that failed is retried this often.
const RETRY_SECS: u64 = 15;
const MAX_REVERT_ATTEMPTS: u8 = 6;
const MIN_PORT: u16 = 1024;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn internal(message: impl ToString) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::Internal, message.to_string())
}

fn firewall_error(err: FirewallError) -> ErrorPayload {
    match err {
        FirewallError::Backend { .. } => internal(err),
        other => bad_request(other.to_string()),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---- state ----------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct StoredLockout {
    threshold: u32,
    window_mins: u32,
    duration_mins: u32,
}

impl From<Lockout> for StoredLockout {
    fn from(l: Lockout) -> Self {
        Self {
            threshold: l.threshold,
            window_mins: l.window_mins,
            duration_mins: l.duration_mins,
        }
    }
}

impl From<StoredLockout> for Lockout {
    fn from(l: StoredLockout) -> Self {
        Self {
            threshold: l.threshold,
            window_mins: l.window_mins,
            duration_mins: l.duration_mins,
        }
    }
}

/// How to undo one change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Revert {
    port: Option<u16>,
    restart_service: bool,
    nla: Option<bool>,
    lockout: Option<StoredLockout>,
    firewall: Option<FirewallSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    id: u64,
    kind: String,
    description: String,
    deadline_secs: u64,
    revert: Revert,
    #[serde(default)]
    attempts: u8,
}

/// The machine as it was before PacketWard first changed anything (written once, never overwritten).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Original {
    port: u16,
    nla: bool,
    lockout: StoredLockout,
    firewall: FirewallSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Saved {
    original: Option<Original>,
    pending: Option<Pending>,
    /// The restriction in force: the allow list and the firewall state from before it.
    restriction: Option<Restriction>,
    attempts: Option<(u32, u32)>,
    next_id: u64,
}

impl Default for Saved {
    fn default() -> Self {
        Self {
            original: None,
            pending: None,
            restriction: None,
            attempts: None,
            next_id: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Restriction {
    allowed: Vec<String>,
    before: FirewallSnapshot,
}

/// What the engine knows at the time of a call.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// TCP ports something listens on (a new RDP port must not be one of them).
    pub listening_ports: Vec<u16>,
    pub logon_audit: LogonAudit,
}

pub struct RdpShield {
    control: Arc<dyn RdpControl>,
    firewall: Arc<dyn Firewall>,
    trust: Arc<TrustState>,
    defense: Arc<Defense>,
    dir: Option<PathBuf>,
    clock: fn() -> u64,
    confirm_secs: u32,
    state: Mutex<Saved>,
}

impl RdpShield {
    pub fn new(
        control: Arc<dyn RdpControl>,
        firewall: Arc<dyn Firewall>,
        trust: Arc<TrustState>,
        defense: Arc<Defense>,
        dir: Option<PathBuf>,
    ) -> Self {
        Self::with_clock(
            control,
            firewall,
            trust,
            defense,
            dir,
            now_secs,
            DEFAULT_CONFIRM_SECS,
        )
    }

    pub fn with_clock(
        control: Arc<dyn RdpControl>,
        firewall: Arc<dyn Firewall>,
        trust: Arc<TrustState>,
        defense: Arc<Defense>,
        dir: Option<PathBuf>,
        clock: fn() -> u64,
        confirm_secs: u32,
    ) -> Self {
        let saved = dir
            .as_ref()
            .and_then(|d| fs::read_to_string(d.join("rdp_shield.json")).ok())
            .and_then(|text| serde_json::from_str::<Saved>(&text).ok())
            .unwrap_or_default();
        Self {
            control,
            firewall,
            trust,
            defense,
            dir,
            clock,
            confirm_secs,
            state: Mutex::new(saved),
        }
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn save(&self, state: &Saved) {
        let Some(dir) = &self.dir else { return };
        let write = || -> std::io::Result<()> {
            fs::create_dir_all(dir)?;
            let tmp = dir.join("rdp_shield.json.tmp");
            fs::write(
                &tmp,
                serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?,
            )?;
            fs::rename(tmp, dir.join("rdp_shield.json"))
        };
        if let Err(err) = write() {
            tracing::error!(%err, "could not save the RDP Shield state");
        }
    }

    fn audit_log(&self, action: &str, detail: &str, result: &str) {
        // The same append-only log as the firewall actions.
        self.defense
            .audit_entry("rdp_shield", action, "rdp", detail, result);
    }

    fn io(err: std::io::Error) -> ErrorPayload {
        internal(err)
    }

    // ---- reading ------------------------------------------------------------------------------

    fn trusted_addresses(&self) -> Vec<IpAddr> {
        self.trust
            .addresses(self.now().saturating_mul(1000))
            .into_iter()
            .filter_map(|a| a.addr.parse::<IpAddr>().ok())
            .collect()
    }

    pub fn audit(&self, inputs: &Inputs) -> Result<RdpAudit, ErrorPayload> {
        let config = self.control.read().map_err(Self::io)?;
        let users = self.control.remote_desktop_users().unwrap_or_default();
        let rules = self
            .firewall
            .list_rules(&RuleFilter::default())
            .map_err(firewall_error)?;
        let port = config.port;
        let builtin_enabled = rules
            .iter()
            .any(|r| pw_firewall::guard::is_builtin_rdp_rule(r) && r.enabled);
        let open_to_any = rules.iter().any(|r| {
            r.enabled
                && r.direction == pw_firewall::Direction::Inbound
                && r.action == pw_firewall::Action::Allow
                && matches!(
                    r.protocol,
                    pw_firewall::Protocol::Tcp | pw_firewall::Protocol::Any
                )
                && (pw_firewall::addr::ports_include(&r.local_ports, port)
                    || pw_firewall::guard::is_builtin_rdp_rule(r))
                && matches!(r.remote_addresses.trim(), "" | "*" | "Any" | "any")
        });
        let state = lock(&self.state);
        let restricted = state.restriction.is_some();
        let allowed = state
            .restriction
            .as_ref()
            .map(|r| r.allowed.clone())
            .unwrap_or_default();
        let attempts = state.attempts.unwrap_or((10, 300));
        let pending = state.pending.as_ref().map(|p| RdpPending {
            id: p.id,
            kind: p.kind.clone(),
            description: p.description.clone(),
            deadline_unix_ms: p.deadline_secs * 1000,
        });
        drop(state);

        let mut findings = Vec::new();
        let mut push = |id: &str, severity: AlertSeverity, value: Option<String>| {
            findings.push(RdpFinding {
                id: id.to_owned(),
                severity,
                value,
            });
        };
        if config.enabled {
            if open_to_any && !restricted {
                push("open_to_any", AlertSeverity::High, Some(port.to_string()));
            }
            if !config.nla_required {
                push("nla_off", AlertSeverity::High, None);
            }
            if config.security_layer == 0 {
                push("weak_security_layer", AlertSeverity::Medium, None);
            }
            if port == DEFAULT_PORT {
                push("default_port", AlertSeverity::Low, Some(port.to_string()));
            }
            if config.lockout.threshold == 0 {
                push("no_lockout", AlertSeverity::Low, None);
            }
            if inputs.logon_audit.failure != pw_proto::AuditState::Enabled {
                push("audit_failures_off", AlertSeverity::Medium, None);
            }
            if inputs.logon_audit.success != pw_proto::AuditState::Enabled {
                push("audit_success_off", AlertSeverity::Medium, None);
            }
            if users.is_empty() {
                push("only_administrators", AlertSeverity::Low, None);
            }
        }
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
        Ok(RdpAudit {
            enabled: config.enabled,
            port,
            nla_required: config.nla_required,
            security_layer: config.security_layer,
            lockout_threshold: config.lockout.threshold,
            lockout_window_mins: config.lockout.window_mins,
            lockout_duration_mins: config.lockout.duration_mins,
            remote_desktop_users: users,
            open_to_any,
            restricted,
            allowed,
            builtin_rules_enabled: builtin_enabled,
            attempts: RdpAttempts {
                threshold: attempts.0,
                window_secs: attempts.1,
            },
            findings,
            pending,
            confirm_secs: self.confirm_secs,
        })
    }

    // ---- transactions -------------------------------------------------------------------------

    /// Saves the factory baseline the first time anything is about to change.
    fn remember_original(&self, config: &RdpConfig, snapshot: &FirewallSnapshot) {
        let mut state = lock(&self.state);
        if state.original.is_none() {
            state.original = Some(Original {
                port: config.port,
                nla: config.nla_required,
                lockout: config.lockout.into(),
                firewall: snapshot.clone(),
            });
            self.save(&state);
        }
    }

    fn start(&self, kind: &str, description: String, revert: Revert) -> Result<(), ErrorPayload> {
        let mut state = lock(&self.state);
        let id = state.next_id;
        state.next_id += 1;
        let deadline = self.now() + u64::from(self.confirm_secs);
        state.pending = Some(Pending {
            id,
            kind: kind.to_owned(),
            description,
            deadline_secs: deadline,
            revert,
            attempts: 0,
        });
        self.save(&state);
        Ok(())
    }

    fn ensure_free(&self) -> Result<(), ErrorPayload> {
        if lock(&self.state).pending.is_some() {
            return Err(ErrorPayload::new(
                ErrorCode::Busy,
                "a change is waiting for confirmation: confirm or cancel it first",
            ));
        }
        Ok(())
    }

    /// Everything that must stay reachable: addresses with a successful RDP logon.
    fn required_clients(&self) -> Vec<IpAddr> {
        self.trusted_addresses()
    }

    fn allowed_list(&self, requested: &[String]) -> Result<Vec<Cidr>, ErrorPayload> {
        let mut allowed: Vec<Cidr> = Vec::new();
        let mut push = |text: &str| -> Result<(), ErrorPayload> {
            let block = text
                .trim()
                .parse::<Cidr>()
                .map_err(|_| bad_request(format!("{text:?} is not an IP address or CIDR block")))?;
            if !allowed.contains(&block) {
                allowed.push(block);
            }
            Ok(())
        };
        for item in requested {
            push(item)?;
        }
        // The people who log in are never locked out of their own restriction.
        for ip in self.required_clients() {
            push(&ip.to_string())?;
        }
        let config = self.defense.allowlist();
        for item in config.allowlist.iter().chain(&config.management) {
            push(item)?;
        }
        Ok(allowed)
    }

    pub fn restrict(&self, request: &RdpRestrictRequest) -> Result<(), ErrorPayload> {
        self.ensure_free()?;
        let config = self.control.read().map_err(Self::io)?;
        let allowed = self.allowed_list(&request.allowed)?;
        if allowed.is_empty() {
            return Err(bad_request(
                "the allow list is empty: that would lock everybody out",
            ));
        }
        let confirmation = request
            .confirmation
            .as_deref()
            .map(|t| Confirmation::from_phrase(t).map_err(firewall_error))
            .transpose()?;
        let before = self
            .firewall
            .rdp_snapshot(self.now())
            .map_err(firewall_error)?;
        self.remember_original(&config, &before);
        let required = self.required_clients();
        let mut opts = RuleOptions::default();
        if let Some(c) = &confirmation {
            opts = opts.confirmed(c);
        }
        let outcome = self
            .firewall
            .rdp_restrict(
                &RdpRestrict {
                    port: config.port,
                    allowed: &allowed,
                    required_clients: &required,
                    include_udp: true,
                    disable_builtin: request.disable_builtin,
                },
                self.now(),
                &opts,
            )
            .map_err(firewall_error)?;
        {
            let mut state = lock(&self.state);
            // Only the very first restriction records the state to go back to.
            let before_all = state
                .restriction
                .as_ref()
                .map_or_else(|| outcome.snapshot.clone(), |r| r.before.clone());
            state.restriction = Some(Restriction {
                allowed: allowed.iter().map(format_cidr).collect(),
                before: before_all,
            });
            self.save(&state);
        }
        self.audit_log(
            "restrict",
            &format!(
                "{} addresses allowed, builtin rules off: {}",
                allowed.len(),
                request.disable_builtin
            ),
            "ok",
        );
        self.start(
            "restrict",
            format!("RDP restricted to {} address(es)", allowed.len()),
            Revert {
                firewall: Some(outcome.snapshot),
                ..Revert::default()
            },
        )
    }

    /// Turns the restriction off (the safe direction: no confirmation timer).
    pub fn unrestrict(&self) -> Result<(), ErrorPayload> {
        self.ensure_free()?;
        let Some(restriction) = lock(&self.state).restriction.clone() else {
            return Ok(());
        };
        self.firewall
            .restore_snapshot(&restriction.before)
            .map_err(firewall_error)?;
        let mut state = lock(&self.state);
        state.restriction = None;
        self.save(&state);
        drop(state);
        self.audit_log("unrestrict", "", "ok");
        Ok(())
    }

    pub fn change_port(
        &self,
        request: &RdpPortRequest,
        inputs: &Inputs,
    ) -> Result<(), ErrorPayload> {
        self.ensure_free()?;
        if !request.i_understand {
            return Err(bad_request(
                "changing the port disconnects every Remote Desktop session; confirm that you understand",
            ));
        }
        let config = self.control.read().map_err(Self::io)?;
        if request.port == config.port {
            return Err(bad_request("that is already the RDP port"));
        }
        if request.port < MIN_PORT && request.port != DEFAULT_PORT {
            return Err(bad_request(format!("choose a port from {MIN_PORT} up")));
        }
        if inputs.listening_ports.contains(&request.port) {
            return Err(bad_request("another program already listens on that port"));
        }
        let before = self
            .firewall
            .rdp_snapshot(self.now())
            .map_err(firewall_error)?;
        self.remember_original(&config, &before);
        // The new port must be reachable before the service moves: open it first, for the same
        // addresses as the current one (everybody when not restricted).
        let restricted_to = lock(&self.state)
            .restriction
            .as_ref()
            .map(|r| r.allowed.clone());
        let allowed: Vec<Cidr> = match &restricted_to {
            Some(list) => list.iter().filter_map(|t| t.parse().ok()).collect(),
            None => ["0.0.0.0/0", "::/0"]
                .iter()
                .filter_map(|t| t.parse().ok())
                .collect(),
        };
        let required = self.required_clients();
        let outcome = self
            .firewall
            .rdp_restrict(
                &RdpRestrict {
                    port: request.port,
                    allowed: &allowed,
                    required_clients: &required,
                    include_udp: true,
                    disable_builtin: false,
                },
                self.now(),
                &RuleOptions::default(),
            )
            .map_err(firewall_error)?;
        let revert = Revert {
            port: Some(config.port),
            restart_service: true,
            firewall: Some(outcome.snapshot),
            ..Revert::default()
        };
        let applied = self
            .control
            .set_port(request.port)
            .and_then(|()| self.control.restart_service());
        if let Err(err) = applied {
            // Put it back right away: the service may be half-way.
            if let Err(problem) = self.run_revert(&revert) {
                self.audit_log("port", &format!("revert incomplete: {problem}"), "failed");
            }
            self.audit_log(
                "port",
                &format!("{} -> {}", config.port, request.port),
                "failed",
            );
            return Err(internal(format!("could not change the port: {err}")));
        }
        self.audit_log(
            "port",
            &format!("{} -> {}", config.port, request.port),
            "ok",
        );
        self.start(
            "port",
            format!("RDP port {} -> {}", config.port, request.port),
            revert,
        )
    }

    pub fn set_nla(&self, required: bool) -> Result<(), ErrorPayload> {
        self.ensure_free()?;
        let config = self.control.read().map_err(Self::io)?;
        if config.nla_required == required {
            return Ok(());
        }
        let before = self
            .firewall
            .rdp_snapshot(self.now())
            .map_err(firewall_error)?;
        self.remember_original(&config, &before);
        self.control.set_nla(required).map_err(Self::io)?;
        self.audit_log(
            "nla",
            &format!("{} -> {required}", config.nla_required),
            "ok",
        );
        self.start(
            "nla",
            format!(
                "Network Level Authentication {}",
                if required { "required" } else { "not required" }
            ),
            Revert {
                nla: Some(config.nla_required),
                ..Revert::default()
            },
        )
    }

    pub fn set_lockout(&self, request: &RdpLockoutRequest) -> Result<(), ErrorPayload> {
        self.ensure_free()?;
        if request.threshold > 0 {
            if !request.understand_dos {
                return Err(bad_request(
                    "account lockout lets an attacker lock a legitimate account on purpose (a denial of service); confirm that you understand",
                ));
            }
            if !(3..=50).contains(&request.threshold)
                || !(1..=1440).contains(&request.window_mins)
                || !(1..=1440).contains(&request.duration_mins)
            {
                return Err(bad_request(
                    "threshold 3-50, observation window and duration 1-1440 minutes",
                ));
            }
        }
        let config = self.control.read().map_err(Self::io)?;
        let before = self
            .firewall
            .rdp_snapshot(self.now())
            .map_err(firewall_error)?;
        self.remember_original(&config, &before);
        let wanted = Lockout {
            threshold: request.threshold,
            window_mins: request.window_mins.max(1),
            duration_mins: request.duration_mins.max(1),
        };
        self.control.set_lockout(wanted).map_err(Self::io)?;
        self.audit_log("lockout", &format!("threshold {}", wanted.threshold), "ok");
        self.start(
            "lockout",
            format!("Account lockout after {} failed logons", wanted.threshold),
            Revert {
                lockout: Some(config.lockout.into()),
                ..Revert::default()
            },
        )
    }

    /// The attempt limit is enforced through the detector (and so the Guardian); nothing on the machine
    /// changes, so it needs no confirmation timer.
    pub fn set_attempts(&self, attempts: RdpAttempts) -> Result<RdpAttempts, ErrorPayload> {
        if !(3..=100).contains(&attempts.threshold) || !(30..=3600).contains(&attempts.window_secs)
        {
            return Err(bad_request("3-100 failures within 30-3600 seconds"));
        }
        let mut state = lock(&self.state);
        state.attempts = Some((attempts.threshold, attempts.window_secs));
        self.save(&state);
        drop(state);
        self.audit_log(
            "attempts",
            &format!("{} in {} s", attempts.threshold, attempts.window_secs),
            "ok",
        );
        Ok(attempts)
    }

    /// The saved attempt limit, to apply to the detectors at start.
    pub fn saved_attempts(&self) -> Option<RdpAttempts> {
        lock(&self.state)
            .attempts
            .map(|(threshold, window_secs)| RdpAttempts {
                threshold,
                window_secs,
            })
    }

    pub fn confirm(&self, id: u64) -> Result<(), ErrorPayload> {
        let mut state = lock(&self.state);
        match &state.pending {
            Some(p) if p.id == id => {
                let kind = p.kind.clone();
                state.pending = None;
                self.save(&state);
                drop(state);
                self.audit_log("confirm", &kind, "ok");
                Ok(())
            }
            _ => Err(bad_request(
                "there is no such change waiting for confirmation (it may have been reverted)",
            )),
        }
    }

    pub fn cancel(&self, id: u64) -> Result<(), ErrorPayload> {
        let pending = {
            let state = lock(&self.state);
            state.pending.clone().filter(|p| p.id == id)
        };
        let Some(pending) = pending else {
            return Err(bad_request(
                "there is no such change waiting for confirmation",
            ));
        };
        self.revert(pending, "cancelled")
    }

    fn run_revert(&self, revert: &Revert) -> Result<(), String> {
        let mut problems = Vec::new();
        if let Some(port) = revert.port {
            if let Err(err) = self.control.set_port(port) {
                problems.push(format!("port: {err}"));
            } else if revert.restart_service {
                if let Err(err) = self.control.restart_service() {
                    problems.push(format!("service restart: {err}"));
                }
            }
        }
        if let Some(nla) = revert.nla {
            if let Err(err) = self.control.set_nla(nla) {
                problems.push(format!("NLA: {err}"));
            }
        }
        if let Some(lockout) = revert.lockout {
            if let Err(err) = self.control.set_lockout(lockout.into()) {
                problems.push(format!("lockout: {err}"));
            }
        }
        if let Some(snapshot) = &revert.firewall {
            if let Err(err) = self.firewall.restore_snapshot(snapshot) {
                problems.push(format!("firewall: {err}"));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems.join("; "))
        }
    }

    fn revert(&self, pending: Pending, why: &str) -> Result<(), ErrorPayload> {
        match self.run_revert(&pending.revert) {
            Ok(()) => {
                let mut state = lock(&self.state);
                if state.pending.as_ref().is_some_and(|p| p.id == pending.id) {
                    state.pending = None;
                }
                if pending.kind == "restrict" || pending.kind == "port" {
                    // The firewall is back to before the change; a restriction made by it is gone too.
                    if pending.kind == "restrict" {
                        state.restriction = None;
                    }
                }
                self.save(&state);
                drop(state);
                self.audit_log("revert", &format!("{} ({why})", pending.kind), "ok");
                Ok(())
            }
            Err(problem) => {
                let mut state = lock(&self.state);
                if let Some(p) = state.pending.as_mut().filter(|p| p.id == pending.id) {
                    p.attempts += 1;
                    p.deadline_secs = self.now() + RETRY_SECS;
                    if p.attempts >= MAX_REVERT_ATTEMPTS {
                        state.pending = None;
                    }
                }
                self.save(&state);
                drop(state);
                self.audit_log(
                    "revert",
                    &format!("{} ({why}): {problem}", pending.kind),
                    "failed",
                );
                Err(internal(format!("could not revert completely: {problem}")))
            }
        }
    }

    /// Reverts every change whose confirmation deadline has passed. Called every second and, first of
    /// all, when the agent starts (a change that outlived a restart was never confirmed).
    pub fn tick(&self) {
        let due = {
            let state = lock(&self.state);
            state
                .pending
                .clone()
                .filter(|p| p.deadline_secs <= self.now())
        };
        if let Some(pending) = due {
            tracing::warn!(kind = %pending.kind, "an RDP change was not confirmed in time: reverting it");
            let _ = self.revert(pending, "not confirmed in time");
        }
    }

    /// Start-up check: a pending change whose deadline passed while the agent was down is reverted now.
    pub fn recover(&self) {
        self.tick();
    }

    /// Restores Remote Desktop to factory state: port 3389, built-in rules enabled, no PacketWard
    /// restriction. NLA and the other Windows settings are left as they are.
    pub fn reset(&self) -> Result<(), ErrorPayload> {
        let mut problems = Vec::new();
        let config = self.control.read().map_err(Self::io)?;
        if config.port != DEFAULT_PORT {
            let moved = self
                .control
                .set_port(DEFAULT_PORT)
                .and_then(|()| self.control.restart_service());
            if let Err(err) = moved {
                problems.push(format!("port: {err}"));
            }
        }
        let (original, restriction) = {
            let state = lock(&self.state);
            (state.original.clone(), state.restriction.clone())
        };
        if let Some(r) = restriction.or_else(|| {
            original.map(|o| Restriction {
                allowed: vec![],
                before: o.firewall,
            })
        }) {
            if let Err(err) = self.firewall.restore_snapshot(&r.before) {
                problems.push(format!("firewall snapshot: {err}"));
            }
        }
        // Whatever the snapshots say, the end state is the built-in rules on and no shield rules.
        let confirmation =
            Confirmation::from_phrase(CONFIRMATION_PHRASE).map_err(firewall_error)?;
        let opts = RuleOptions::default().confirmed(&confirmation);
        if let Err(err) = self.firewall.set_builtin_rdp_enabled(true, &opts) {
            problems.push(format!("built-in rules: {err}"));
        }
        for name in ["PW-RDP-Allow", "PW-RDP-Allow-UDP"] {
            match self.firewall.remove_rule(name, &opts) {
                Ok(()) | Err(FirewallError::NotFound(_)) => {}
                Err(err) => problems.push(format!("{name}: {err}")),
            }
        }
        {
            let mut state = lock(&self.state);
            state.pending = None;
            state.restriction = None;
            self.save(&state);
        }
        if problems.is_empty() {
            self.audit_log("reset", "", "ok");
            Ok(())
        } else {
            self.audit_log("reset", &problems.join("; "), "failed");
            Err(internal(format!(
                "reset incomplete: {}",
                problems.join("; ")
            )))
        }
    }

    pub fn end_session(&self, request: &RdpEndSessionRequest) -> Result<(), ErrorPayload> {
        let result = self.control.end_session(request.session_id, request.logoff);
        self.audit_log(
            if request.logoff {
                "logoff"
            } else {
                "disconnect"
            },
            &format!("session {}", request.session_id),
            if result.is_ok() { "ok" } else { "failed" },
        );
        result.map_err(Self::io)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use pw_firewall::fake::FakeFirewall;
    use pw_firewall::FirewallManager;
    use pw_netstat::rdp_control::{FakeRdpControl, RdpCall};
    use pw_netstat::NetworkContext;
    use pw_proto::AuditState;

    use super::*;
    use crate::defense::MemoryPersistence;

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(0) };
    }

    fn clock() -> u64 {
        NOW.with(Cell::get)
    }

    fn advance(secs: u64) {
        NOW.with(|n| n.set(n.get() + secs));
    }

    struct Rig {
        shield: RdpShield,
        control: Arc<FakeRdpControl>,
        firewall: Arc<FirewallManager<FakeFirewall>>,
        trust: Arc<TrustState>,
        defense: Arc<Defense>,
        dir: tempfile::TempDir,
    }

    fn rig_in(dir: tempfile::TempDir) -> Rig {
        NOW.with(|n| n.set(now_secs()));
        let control = Arc::new(FakeRdpControl::new());
        let firewall = Arc::new(FirewallManager::new(FakeFirewall::windows_defaults()));
        let trust = TrustState::new(30);
        let defense = Arc::new(Defense::with_clock(
            Arc::clone(&firewall) as Arc<dyn Firewall>,
            Arc::new(MemoryPersistence::default()),
            Arc::new(std::sync::RwLock::new(NetworkContext::default())),
            Arc::clone(&trust),
            clock,
        ));
        let shield = RdpShield::with_clock(
            Arc::clone(&control) as Arc<dyn RdpControl>,
            Arc::clone(&firewall) as Arc<dyn Firewall>,
            Arc::clone(&trust),
            Arc::clone(&defense),
            Some(dir.path().to_path_buf()),
            clock,
            120,
        );
        Rig {
            defense: Arc::clone(&defense),
            shield,
            control,
            firewall,
            trust,
            dir,
        }
    }

    fn rig() -> Rig {
        rig_in(tempfile::tempdir().unwrap())
    }

    fn trusted(rig: &Rig, ip: &str) {
        rig.trust.sink()(pw_netstat::logon::LogonEvent {
            addr: ip.parse().unwrap(),
            at_unix_ms: clock() * 1000,
        });
    }

    fn inputs() -> Inputs {
        Inputs {
            listening_ports: vec![80, 443, 3389],
            logon_audit: LogonAudit {
                success: AuditState::Enabled,
                failure: AuditState::Enabled,
            },
        }
    }

    fn builtin_enabled(rig: &Rig) -> bool {
        rig.firewall
            .backend()
            .rules()
            .iter()
            .filter(|r| pw_firewall::guard::is_builtin_rdp_rule(r))
            .all(|r| r.enabled)
    }

    #[test]
    fn the_audit_reports_what_is_exposed_with_findings_by_severity() {
        let rig = rig();
        let audit = rig.shield.audit(&inputs()).unwrap();
        assert!(audit.enabled && audit.open_to_any && audit.builtin_rules_enabled);
        let ids: Vec<&str> = audit.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"open_to_any")
                && ids.contains(&"default_port")
                && ids.contains(&"no_lockout"),
            "{ids:?}"
        );
        assert!(
            audit
                .findings
                .windows(2)
                .all(|w| w[0].severity >= w[1].severity),
            "worst first"
        );

        let quiet = rig
            .shield
            .audit(&Inputs {
                logon_audit: LogonAudit::default(),
                ..inputs()
            })
            .unwrap();
        assert!(quiet.findings.iter().any(|f| f.id == "audit_failures_off"));
    }

    #[test]
    fn nla_off_is_a_high_finding() {
        let rig = rig();
        rig.control.set_nla(false).unwrap();
        let audit = rig.shield.audit(&inputs()).unwrap();
        let nla = audit.findings.iter().find(|f| f.id == "nla_off").unwrap();
        assert_eq!(nla.severity, AlertSeverity::High);
    }

    #[test]
    fn restricting_needs_a_trusted_client_and_always_includes_it() {
        let rig = rig();
        let err = rig
            .shield
            .restrict(&RdpRestrictRequest {
                allowed: vec!["203.0.113.0/24".into()],
                disable_builtin: true,
                confirmation: Some(CONFIRMATION_PHRASE.into()),
            })
            .unwrap_err();
        assert!(!err.message.is_empty());
        assert!(
            rig.firewall.backend().writes().is_empty(),
            "nothing changed"
        );

        trusted(&rig, "198.51.100.77");
        rig.shield
            .restrict(&RdpRestrictRequest {
                allowed: vec!["203.0.113.0/24".into()],
                disable_builtin: false,
                confirmation: None,
            })
            .unwrap();
        let audit = rig.shield.audit(&inputs()).unwrap();
        assert!(audit.restricted);
        assert!(
            audit.allowed.contains(&"198.51.100.77/32".to_owned()),
            "{:?}",
            audit.allowed
        );
        assert!(audit.allowed.contains(&"203.0.113.0/24".to_owned()));
        assert!(audit.pending.is_some());
    }

    #[test]
    fn disabling_the_builtin_rules_needs_the_typed_phrase() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        let request = RdpRestrictRequest {
            allowed: vec![],
            disable_builtin: true,
            confirmation: None,
        };
        assert!(rig.shield.restrict(&request).is_err());
        assert!(builtin_enabled(&rig));
        rig.shield
            .restrict(&RdpRestrictRequest {
                confirmation: Some(CONFIRMATION_PHRASE.into()),
                ..request
            })
            .unwrap();
        assert!(!builtin_enabled(&rig));
    }

    #[test]
    fn an_unconfirmed_restriction_is_reverted_by_the_agent() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.shield
            .restrict(&RdpRestrictRequest {
                allowed: vec![],
                disable_builtin: true,
                confirmation: Some(CONFIRMATION_PHRASE.into()),
            })
            .unwrap();
        assert!(!builtin_enabled(&rig));
        advance(119);
        rig.shield.tick();
        assert!(!builtin_enabled(&rig), "still waiting for confirmation");
        advance(2);
        rig.shield.tick();
        assert!(builtin_enabled(&rig), "back to how it was");
        let audit = rig.shield.audit(&inputs()).unwrap();
        assert!(!audit.restricted && audit.pending.is_none());
        assert!(rig
            .firewall
            .backend()
            .rules()
            .iter()
            .all(|r| !r.name.starts_with("PW-RDP-Allow")));
    }

    #[test]
    fn a_confirmed_restriction_stays_and_only_one_change_waits_at_a_time() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.shield
            .restrict(&RdpRestrictRequest {
                allowed: vec![],
                disable_builtin: false,
                confirmation: None,
            })
            .unwrap();
        let id = rig.shield.audit(&inputs()).unwrap().pending.unwrap().id;
        let busy = rig.shield.set_nla(false).unwrap_err();
        assert_eq!(busy.code, ErrorCode::Busy);
        assert!(rig.shield.confirm(id + 5).is_err());
        rig.shield.confirm(id).unwrap();
        advance(1000);
        rig.shield.tick();
        assert!(rig.shield.audit(&inputs()).unwrap().restricted);
        // And it can be turned off again, which restores the firewall as it was.
        rig.shield.unrestrict().unwrap();
        assert!(!rig.shield.audit(&inputs()).unwrap().restricted);
        assert!(rig
            .firewall
            .backend()
            .rules()
            .iter()
            .all(|r| !r.name.starts_with("PW-RDP-Allow")));
    }

    #[test]
    fn changing_the_port_opens_the_new_one_first_and_reverts_when_unconfirmed() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.shield
            .change_port(
                &RdpPortRequest {
                    port: 43389,
                    i_understand: true,
                },
                &inputs(),
            )
            .unwrap();
        let calls = rig.control.calls();
        assert_eq!(calls, [RdpCall::SetPort(43389), RdpCall::RestartService]);
        assert!(rig
            .firewall
            .backend()
            .rules()
            .iter()
            .any(|r| r.name == "PW-RDP-Allow" && r.local_ports == "43389"));
        assert_eq!(rig.shield.audit(&inputs()).unwrap().port, 43389);
        advance(121);
        rig.shield.tick();
        assert_eq!(
            rig.control.read().unwrap().port,
            3389,
            "the agent put the port back"
        );
        assert_eq!(rig.control.calls().last(), Some(&RdpCall::RestartService));
        assert!(rig
            .firewall
            .backend()
            .rules()
            .iter()
            .all(|r| !r.name.starts_with("PW-RDP-Allow")));
    }

    #[test]
    fn port_changes_are_validated_before_anything_happens() {
        let rig = rig();
        let ask = |port: u16, ok: bool| {
            rig.shield.change_port(
                &RdpPortRequest {
                    port,
                    i_understand: ok,
                },
                &inputs(),
            )
        };
        assert!(ask(43389, false).is_err(), "needs the acknowledgement");
        assert!(ask(3389, true).is_err(), "already the port");
        assert!(ask(22, true).is_err(), "privileged range");
        assert!(ask(443, true).is_err(), "in use");
        assert!(rig.control.calls().is_empty());
        assert!(rig.firewall.backend().writes().is_empty());
    }

    #[test]
    fn a_failed_service_restart_reverts_at_once() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.control.fail_next("restart");
        let err = rig
            .shield
            .change_port(
                &RdpPortRequest {
                    port: 43389,
                    i_understand: true,
                },
                &inputs(),
            )
            .unwrap_err();
        assert!(err.message.contains("could not change the port"));
        assert_eq!(rig.control.read().unwrap().port, 3389);
        assert!(rig.shield.audit(&inputs()).unwrap().pending.is_none());
    }

    #[test]
    fn nla_and_lockout_are_reverted_too_and_lockout_needs_the_dos_acknowledgement() {
        let rig = rig();
        rig.shield.set_nla(false).unwrap();
        advance(121);
        rig.shield.tick();
        assert!(rig.control.read().unwrap().nla_required);

        let request = RdpLockoutRequest {
            threshold: 10,
            window_mins: 15,
            duration_mins: 15,
            understand_dos: false,
        };
        assert!(rig.shield.set_lockout(&request).is_err());
        assert!(rig
            .shield
            .set_lockout(&RdpLockoutRequest {
                understand_dos: true,
                threshold: 1,
                ..request.clone()
            })
            .is_err());
        rig.shield
            .set_lockout(&RdpLockoutRequest {
                understand_dos: true,
                ..request
            })
            .unwrap();
        assert_eq!(rig.control.read().unwrap().lockout.threshold, 10);
        advance(121);
        rig.shield.tick();
        assert_eq!(
            rig.control.read().unwrap().lockout.threshold,
            0,
            "back to off"
        );
    }

    #[test]
    fn a_pending_change_survives_a_restart_and_is_reverted_on_start() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.shield
            .restrict(&RdpRestrictRequest {
                allowed: vec![],
                disable_builtin: true,
                confirmation: Some(CONFIRMATION_PHRASE.into()),
            })
            .unwrap();
        assert!(!builtin_enabled(&rig));
        // The agent dies and a new one starts on the same machine, reading the saved state. The change
        // was never confirmed and its deadline has passed: the new agent undoes it before anything else.
        advance(300);
        let restarted = RdpShield::with_clock(
            Arc::clone(&rig.control) as Arc<dyn RdpControl>,
            Arc::clone(&rig.firewall) as Arc<dyn Firewall>,
            Arc::clone(&rig.trust),
            Arc::clone(&rig.defense),
            Some(rig.dir.path().to_path_buf()),
            clock,
            120,
        );
        assert!(
            restarted.audit(&inputs()).unwrap().pending.is_some(),
            "the pending change was remembered"
        );
        restarted.recover();
        assert!(builtin_enabled(&rig), "back to how it was");
        assert!(restarted.audit(&inputs()).unwrap().pending.is_none());
    }

    #[test]
    fn reset_restores_the_factory_state_even_after_several_changes() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.shield
            .restrict(&RdpRestrictRequest {
                allowed: vec![],
                disable_builtin: true,
                confirmation: Some(CONFIRMATION_PHRASE.into()),
            })
            .unwrap();
        let id = rig.shield.audit(&inputs()).unwrap().pending.unwrap().id;
        rig.shield.confirm(id).unwrap();
        rig.shield
            .change_port(
                &RdpPortRequest {
                    port: 43389,
                    i_understand: true,
                },
                &inputs(),
            )
            .unwrap();
        let id = rig.shield.audit(&inputs()).unwrap().pending.unwrap().id;
        rig.shield.confirm(id).unwrap();
        assert_eq!(rig.control.read().unwrap().port, 43389);
        assert!(!builtin_enabled(&rig));

        rig.shield.reset().unwrap();
        assert_eq!(rig.control.read().unwrap().port, 3389);
        assert!(builtin_enabled(&rig));
        assert!(rig
            .firewall
            .backend()
            .rules()
            .iter()
            .all(|r| !r.name.starts_with("PW-RDP-Allow")));
        let audit = rig.shield.audit(&inputs()).unwrap();
        assert!(!audit.restricted && audit.pending.is_none());
        rig.shield.reset().unwrap(); // idempotent
    }

    #[test]
    fn the_original_state_is_written_once_and_never_overwritten() {
        let rig = rig();
        trusted(&rig, "198.51.100.77");
        rig.shield.set_nla(false).unwrap();
        let first = fs::read_to_string(rig.dir.path().join("rdp_shield.json")).unwrap();
        let first: Saved = serde_json::from_str(&first).unwrap();
        assert!(
            first.original.as_ref().unwrap().nla,
            "the original had NLA on"
        );
        let id = first.pending.unwrap().id;
        rig.shield.confirm(id).unwrap();
        rig.shield.set_nla(true).unwrap(); // a later change
        let later: Saved = serde_json::from_str(
            &fs::read_to_string(rig.dir.path().join("rdp_shield.json")).unwrap(),
        )
        .unwrap();
        assert!(later.original.unwrap().nla);
    }

    #[test]
    fn the_attempt_limit_is_validated_and_remembered() {
        let rig = rig();
        assert!(rig
            .shield
            .set_attempts(RdpAttempts {
                threshold: 1,
                window_secs: 300
            })
            .is_err());
        assert!(rig
            .shield
            .set_attempts(RdpAttempts {
                threshold: 5,
                window_secs: 10
            })
            .is_err());
        rig.shield
            .set_attempts(RdpAttempts {
                threshold: 5,
                window_secs: 120,
            })
            .unwrap();
        assert_eq!(rig.shield.saved_attempts().unwrap().threshold, 5);
        assert_eq!(
            rig.shield.audit(&inputs()).unwrap().attempts.window_secs,
            120
        );
    }

    #[test]
    fn sessions_can_be_disconnected_or_logged_off() {
        let rig = rig();
        rig.shield
            .end_session(&RdpEndSessionRequest {
                session_id: 3,
                logoff: false,
            })
            .unwrap();
        rig.shield
            .end_session(&RdpEndSessionRequest {
                session_id: 4,
                logoff: true,
            })
            .unwrap();
        assert_eq!(
            rig.control.calls(),
            [
                RdpCall::EndSession {
                    id: 3,
                    logoff: false
                },
                RdpCall::EndSession {
                    id: 4,
                    logoff: true
                }
            ]
        );
        rig.control.fail_next("end_session");
        assert!(rig
            .shield
            .end_session(&RdpEndSessionRequest {
                session_id: 5,
                logoff: true
            })
            .is_err());
    }
}
