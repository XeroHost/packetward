// SPDX-License-Identifier: GPL-3.0-or-later
//! RDP Shield country restriction (M7b, decision RS-2): an optional, reactive rule.
//!
//! The GeoIP database only knows countries (no ranges) and Windows Firewall cannot filter by country,
//! so the restriction cannot be a firewall allow list. Instead [`CountryGuard`] looks at the public
//! addresses that are connected to the RDP port (and at the sources of recent failed-logon incidents),
//! asks the local GeoIP database for their country and, when the country breaks the policy, hands the
//! address to the Guardian ([`Defense::guard_address`]): the same protected set, Monitor report, TTL,
//! circuit breaker and audit as every other automatic block.
//!
//! Fail closed, everywhere: the policy is off unless a readable file says otherwise, an address whose
//! country is unknown is never blocked, a missing or corrupt GeoIP database blocks nothing, and an
//! address the Guardian protects (successful RDP logon, allowlist, gateway, DNS, loopback, management
//! ranges) is never a candidate.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use pw_intel::net::is_public_ip;
use pw_proto::{
    ErrorCode, ErrorPayload, GuardianDecision, RdpCountryMode, RdpCountryPolicy, RdpCountryStatus,
};

use crate::defense::Defense;
use crate::intel::IntelApi;

/// What the Guardian's decisions show for this rule.
pub const SUMMARY_KEY: &str = "rdp_country";
/// At most this many countries in a policy (there are fewer than 250 ISO regions).
pub const MAX_COUNTRIES: usize = 300;
/// How often the enforcement loop wakes up while the policy is on.
pub const TICK_SECS: u64 = 5;
/// A failed-logon incident older than this does not make its source a candidate.
pub const RECENT_INCIDENT_MS: u64 = 60 * 60 * 1000;
/// An address the Guardian could not act on (circuit open, firewall refused) is retried after this.
const RETRY_SECS: u64 = 300;
/// A Monitor "would block" is not repeated for the same address within this time.
const MONITOR_MEMORY_SECS: u64 = 3600;
/// Candidates examined per tick (a flood of peers must not stall the loop).
const MAX_CANDIDATES: usize = 200;
const FILE_NAME: &str = "rdp_country.json";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---- the seam -------------------------------------------------------------------------------------

/// Where countries come from. Local lookups only: it must never reach the network.
pub trait CountrySource: Send + Sync {
    /// The ISO alpha-2 country of a public address, `None` when it is unknown.
    fn country_of(&self, ip: IpAddr) -> Option<String>;
    /// The GeoIP database is installed and readable.
    fn ready(&self) -> bool;
}

/// The intel service as a [`CountrySource`].
pub struct IntelCountries(pub Arc<dyn IntelApi>);

impl CountrySource for IntelCountries {
    fn country_of(&self, ip: IpAddr) -> Option<String> {
        self.0
            .lookup_one(ip)
            .and_then(|(_, _, country)| country)
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| valid_code(c))
    }

    fn ready(&self) -> bool {
        self.0.geo_status().state == "ready"
    }
}

/// What one pass looks at, gathered by the engine from the latest snapshot and the alert store.
#[derive(Debug, Clone, Default)]
pub struct CountryInputs {
    /// Addresses connected to the RDP port right now.
    pub peers: Vec<IpAddr>,
    /// Sources of recent RDP failed-logon incidents.
    pub failed_logon_sources: Vec<IpAddr>,
}

// ---- the policy -----------------------------------------------------------------------------------

fn valid_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// A policy as it may be stored: codes valid (2 upper-case letters, at most [`MAX_COUNTRIES`], sorted,
/// without repeats) and, when it is on, not able to block everybody (`allow` with no country).
pub fn validate_policy(policy: RdpCountryPolicy) -> Result<RdpCountryPolicy, ErrorPayload> {
    if policy.countries.len() > MAX_COUNTRIES {
        return Err(bad_request(format!(
            "at most {MAX_COUNTRIES} countries in the list"
        )));
    }
    let mut countries = BTreeSet::new();
    for code in &policy.countries {
        let code = code.trim();
        if !valid_code(code) {
            return Err(bad_request(format!(
                "{code:?} is not a country code (two upper-case letters, for example US)"
            )));
        }
        countries.insert(code.to_owned());
    }
    if policy.enabled && policy.mode == RdpCountryMode::Allow && countries.is_empty() {
        return Err(bad_request(
            "an allow list with no country would block everybody: choose at least one country",
        ));
    }
    Ok(RdpCountryPolicy {
        countries: countries.into_iter().collect(),
        ..policy
    })
}

/// Reads the saved policy; anything missing, unreadable or invalid means **off**.
fn load_policy(dir: Option<&PathBuf>) -> RdpCountryPolicy {
    let Some(dir) = dir else {
        return RdpCountryPolicy::default();
    };
    let Ok(text) = fs::read_to_string(dir.join(FILE_NAME)) else {
        return RdpCountryPolicy::default();
    };
    match serde_json::from_str::<RdpCountryPolicy>(&text)
        .map_err(|e| e.to_string())
        .and_then(|p| validate_policy(p).map_err(|e| e.message))
    {
        Ok(policy) => policy,
        Err(err) => {
            tracing::warn!(%err, "rdp_country.json is not valid; the country restriction stays off");
            RdpCountryPolicy::default()
        }
    }
}

fn save_policy(dir: Option<&PathBuf>, policy: &RdpCountryPolicy) -> std::io::Result<()> {
    let Some(dir) = dir else { return Ok(()) };
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{FILE_NAME}.tmp"));
    fs::write(
        &tmp,
        serde_json::to_vec_pretty(policy).map_err(std::io::Error::other)?,
    )?;
    fs::rename(tmp, dir.join(FILE_NAME))
}

/// Does `country` break the policy? An off policy never does.
pub fn violates(policy: &RdpCountryPolicy, country: &str) -> bool {
    if !policy.enabled {
        return false;
    }
    let listed = policy.countries.iter().any(|c| c == country);
    match policy.mode {
        RdpCountryMode::Allow => !listed,
        RdpCountryMode::Deny => listed,
    }
}

// ---- the service ----------------------------------------------------------------------------------

pub struct CountryGuard {
    defense: Arc<Defense>,
    countries: Arc<dyn CountrySource>,
    dir: Option<PathBuf>,
    clock: fn() -> u64,
    policy: Mutex<RdpCountryPolicy>,
    /// Address → unix seconds until which it is not decided again.
    decided: Mutex<HashMap<IpAddr, u64>>,
}

impl CountryGuard {
    pub fn new(
        defense: Arc<Defense>,
        countries: Arc<dyn CountrySource>,
        dir: Option<PathBuf>,
    ) -> Self {
        Self::with_clock(defense, countries, dir, now_secs)
    }

    pub fn with_clock(
        defense: Arc<Defense>,
        countries: Arc<dyn CountrySource>,
        dir: Option<PathBuf>,
        clock: fn() -> u64,
    ) -> Self {
        let policy = load_policy(dir.as_ref());
        Self {
            defense,
            countries,
            dir,
            clock,
            policy: Mutex::new(policy),
            decided: Mutex::new(HashMap::new()),
        }
    }

    pub fn policy(&self) -> RdpCountryPolicy {
        lock(&self.policy).clone()
    }

    /// The loop only wakes up (and only looks anything up) while this is true.
    pub fn enabled(&self) -> bool {
        lock(&self.policy).enabled
    }

    /// Countries of the protected addresses among `peers`: the operator's own connections.
    fn operator_countries(&self, peers: &[IpAddr]) -> Vec<String> {
        let protected = self.defense.protected_set();
        let found: BTreeSet<String> = peers
            .iter()
            .map(|ip| ip.to_canonical())
            .filter(|ip| is_public_ip(*ip) && protected.contains(*ip))
            .filter_map(|ip| self.countries.country_of(ip))
            .collect();
        found.into_iter().collect()
    }

    pub fn status(&self, peers: &[IpAddr]) -> RdpCountryStatus {
        let (blocked_24h, would_block_24h) = self.defense.decision_counts_24h(SUMMARY_KEY);
        RdpCountryStatus {
            policy: self.policy(),
            geo_ready: self.countries.ready(),
            operator_countries: self.operator_countries(peers),
            blocked_24h,
            would_block_24h,
        }
    }

    /// Saves a new policy. In `allow` mode it is refused when it would exclude the country of a
    /// protected address that is connected to RDP right now (the operator would be cut off by the
    /// next address of the same country: the UI warns, the agent refuses).
    pub fn set_policy(
        &self,
        requested: RdpCountryPolicy,
        peers: &[IpAddr],
        actor: &str,
    ) -> Result<RdpCountryStatus, ErrorPayload> {
        let policy = validate_policy(requested).inspect_err(|err| {
            self.defense
                .audit_entry(actor, "rdp_country", "-", &err.message, "refused");
        })?;
        if policy.enabled && policy.mode == RdpCountryMode::Allow {
            let excluded: Vec<String> = self
                .operator_countries(peers)
                .into_iter()
                .filter(|c| !policy.countries.contains(c))
                .collect();
            if !excluded.is_empty() {
                let message = format!(
                    "this list leaves out {}, where your own Remote Desktop connection comes from: add it or you would be locked out on your next connection from another address there",
                    excluded.join(", ")
                );
                self.defense
                    .audit_entry(actor, "rdp_country", "-", &message, "refused");
                return Err(bad_request(message));
            }
        }
        save_policy(self.dir.as_ref(), &policy).map_err(|err| {
            ErrorPayload::new(
                ErrorCode::Internal,
                format!("could not save the country restriction: {err}"),
            )
        })?;
        let changed = {
            let mut current = lock(&self.policy);
            let changed = *current != policy;
            *current = policy.clone();
            changed
        };
        // A new policy judges everybody again.
        lock(&self.decided).clear();
        if changed {
            self.defense.audit_entry(
                actor,
                "rdp_country",
                "-",
                &format!(
                    "{}, {:?}, {} countries",
                    if policy.enabled { "on" } else { "off" },
                    policy.mode,
                    policy.countries.len()
                )
                .to_lowercase(),
                "ok",
            );
        }
        Ok(self.status(peers))
    }

    /// One enforcement pass (blocking: it may write firewall rules). Returns the decisions taken.
    pub fn tick(&self, inputs: &CountryInputs) -> Vec<GuardianDecision> {
        let policy = self.policy();
        if !policy.enabled || !self.countries.ready() {
            return Vec::new();
        }
        let now = (self.clock)();
        let protected = self.defense.protected_set();
        let candidates: BTreeSet<IpAddr> = {
            let mut decided = lock(&self.decided);
            decided.retain(|_, until| *until > now);
            inputs
                .peers
                .iter()
                .chain(&inputs.failed_logon_sources)
                .map(|ip| ip.to_canonical())
                .filter(|ip| is_public_ip(*ip) && !protected.contains(*ip))
                .filter(|ip| !decided.contains_key(ip))
                .take(MAX_CANDIDATES)
                .collect()
        };
        let mut decisions = Vec::new();
        for ip in candidates {
            // Unknown country (no entry, or no database): never blocked.
            let Some(country) = self.countries.country_of(ip) else {
                continue;
            };
            if !violates(&policy, &country) {
                continue;
            }
            let Some(decision) =
                self.defense
                    .guard_address(ip, SUMMARY_KEY, &format!("rdp_country:{country}"))
            else {
                continue; // The Guardian is Off.
            };
            let ttl = decision.ttl_secs.unwrap_or(RETRY_SECS);
            let hold = match decision.outcome.as_str() {
                "blocked" => ttl,
                "would_block" => ttl.max(MONITOR_MEMORY_SECS),
                _ => RETRY_SECS,
            };
            lock(&self.decided).insert(ip, now + hold);
            decisions.push(decision);
        }
        decisions
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::RwLock;

    use pw_firewall::fake::FakeFirewall;
    use pw_firewall::{BatchId, Firewall, FirewallManager};
    use pw_netstat::NetworkContext;
    use pw_proto::{AllowlistConfig, GuardianMode, GuardianPolicy, SetGuardianPolicy};

    use super::*;
    use crate::defense::MemoryPersistence;
    use crate::trust::TrustState;

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(0) };
    }

    fn clock() -> u64 {
        NOW.with(Cell::get)
    }

    fn advance(secs: u64) {
        NOW.with(|n| n.set(n.get() + secs));
    }

    /// A GeoIP database that knows the countries it is told about.
    struct FakeCountries {
        known: Mutex<HashMap<IpAddr, String>>,
        ready: AtomicBool,
    }

    impl FakeCountries {
        fn new(entries: &[(&str, &str)]) -> Arc<Self> {
            Arc::new(Self {
                known: Mutex::new(
                    entries
                        .iter()
                        .map(|(ip, cc)| (ip.parse().unwrap(), (*cc).to_owned()))
                        .collect(),
                ),
                ready: AtomicBool::new(true),
            })
        }
    }

    impl CountrySource for FakeCountries {
        fn country_of(&self, ip: IpAddr) -> Option<String> {
            if !self.ready.load(Ordering::SeqCst) {
                return None;
            }
            lock(&self.known).get(&ip).cloned()
        }
        fn ready(&self) -> bool {
            self.ready.load(Ordering::SeqCst)
        }
    }

    struct Rig {
        guard: CountryGuard,
        defense: Arc<Defense>,
        firewall: Arc<FirewallManager<FakeFirewall>>,
        trust: Arc<TrustState>,
        geo: Arc<FakeCountries>,
        dir: tempfile::TempDir,
    }

    const GATEWAY: &str = "143.20.99.1";
    const CN: &str = "14.1.1.10";
    const CN2: &str = "14.1.1.11";
    const RU: &str = "95.1.1.20";
    const US: &str = "8.8.8.8";
    const NOWHERE: &str = "9.9.9.9";

    fn rig() -> Rig {
        rig_in(tempfile::tempdir().unwrap())
    }

    fn rig_in(dir: tempfile::TempDir) -> Rig {
        NOW.with(|n| n.set(now_secs()));
        let firewall = Arc::new(FirewallManager::new(FakeFirewall::windows_defaults()));
        let context = Arc::new(RwLock::new(NetworkContext {
            gateways: vec![GATEWAY.parse().unwrap()],
            dns_servers: vec![],
        }));
        let trust = TrustState::new(30);
        let defense = Arc::new(Defense::with_clock(
            Arc::clone(&firewall) as Arc<dyn Firewall>,
            Arc::new(MemoryPersistence::default()),
            context,
            Arc::clone(&trust),
            clock,
        ));
        let geo = FakeCountries::new(&[
            (CN, "CN"),
            (CN2, "CN"),
            (RU, "RU"),
            (US, "US"),
            (GATEWAY, "CN"),
        ]);
        let guard = CountryGuard::with_clock(
            Arc::clone(&defense),
            Arc::clone(&geo) as Arc<dyn CountrySource>,
            Some(dir.path().to_path_buf()),
            clock,
        );
        Rig {
            guard,
            defense,
            firewall,
            trust,
            geo,
            dir,
        }
    }

    fn policy(enabled: bool, mode: RdpCountryMode, countries: &[&str]) -> RdpCountryPolicy {
        RdpCountryPolicy {
            enabled,
            mode,
            countries: countries.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    fn set(rig: &Rig, p: RdpCountryPolicy) {
        rig.guard.set_policy(p, &[], "test").unwrap();
    }

    fn guardian(rig: &Rig, mode: GuardianMode, max_per_hour: u32) {
        let policy = GuardianPolicy {
            mode,
            max_blocks_per_hour: max_per_hour,
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

    fn trusted(rig: &Rig, ip: &str) {
        rig.trust.sink()(pw_netstat::logon::LogonEvent {
            addr: ip.parse().unwrap(),
            at_unix_ms: clock() * 1000,
        });
    }

    fn peers(ips: &[&str]) -> CountryInputs {
        CountryInputs {
            peers: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            failed_logon_sources: vec![],
        }
    }

    fn blocked(rig: &Rig) -> Vec<String> {
        let mut all: Vec<String> = rig
            .firewall
            .list_blocks(&BatchId::auto_block())
            .unwrap()
            .iter()
            .map(pw_firewall::addr::format_cidr)
            .collect();
        all.sort();
        all
    }

    #[test]
    fn it_is_off_by_default_and_does_nothing() {
        let rig = rig();
        assert_eq!(rig.guard.policy(), RdpCountryPolicy::default());
        assert!(!rig.guard.enabled());
        guardian(&rig, GuardianMode::Active, 20);
        assert!(rig.guard.tick(&peers(&[CN, RU, US])).is_empty());
        assert!(blocked(&rig).is_empty());
        assert!(rig.firewall.backend().writes().is_empty());
    }

    #[test]
    fn deny_mode_blocks_the_listed_countries_only() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        let decisions = rig.guard.tick(&peers(&[CN, RU, US]));
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].source, CN);
        assert_eq!(decisions[0].outcome, "blocked");
        assert_eq!(decisions[0].summary_key, SUMMARY_KEY);
        assert_eq!(blocked(&rig), ["14.1.1.10/32"]);
    }

    #[test]
    fn allow_mode_blocks_every_other_known_country() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        set(&rig, policy(true, RdpCountryMode::Allow, &["US"]));
        rig.guard.tick(&peers(&[CN, RU, US]));
        assert_eq!(blocked(&rig), ["14.1.1.10/32", "95.1.1.20/32"]);
    }

    #[test]
    fn failed_logon_sources_are_candidates_too() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        set(&rig, policy(true, RdpCountryMode::Deny, &["RU"]));
        let inputs = CountryInputs {
            peers: vec![],
            failed_logon_sources: vec![RU.parse().unwrap()],
        };
        rig.guard.tick(&inputs);
        assert_eq!(blocked(&rig), ["95.1.1.20/32"]);
    }

    #[test]
    fn the_block_has_a_ttl_the_reason_and_an_audit_entry_and_is_made_once() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        let first = rig.guard.tick(&peers(&[CN]));
        let ttl = first[0].ttl_secs.unwrap();
        assert_eq!(ttl, GuardianPolicy::default().ttl_ladder_secs[0]);
        let list = rig.defense.list_blocks();
        assert_eq!(list.blocks.len(), 1);
        assert_eq!(list.blocks[0].reason, "rdp_country:CN");
        assert_eq!(list.blocks[0].expires_unix_ms, Some((clock() + ttl) * 1000));
        let (entries, _) = rig.defense.audit_entries(50, Some(CN));
        assert!(
            entries
                .iter()
                .any(|e| e.actor == "guardian" && e.action == "block" && e.result == "ok"),
            "{entries:?}"
        );
        // The same address within its TTL is not decided again.
        advance(30);
        assert!(rig.guard.tick(&peers(&[CN])).is_empty());
        assert_eq!(rig.defense.list_blocks().blocks.len(), 1);
        assert_eq!(rig.defense.decision_counts_24h(SUMMARY_KEY), (1, 0));
        // After the block ran out, an address that is still there is judged again.
        advance(ttl + 1);
        rig.defense.reconcile().unwrap();
        assert!(blocked(&rig).is_empty());
        assert_eq!(rig.guard.tick(&peers(&[CN])).len(), 1);
        assert_eq!(blocked(&rig), ["14.1.1.10/32"]);
    }

    #[test]
    fn monitor_records_would_block_and_blocks_nothing() {
        let rig = rig();
        assert_eq!(rig.defense.policy().mode, GuardianMode::Monitor);
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        let decisions = rig.guard.tick(&peers(&[CN, US]));
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "would_block");
        assert!(blocked(&rig).is_empty());
        assert!(rig.defense.list_blocks().blocks.is_empty());
        assert!(rig.firewall.backend().writes().is_empty());
        assert_eq!(rig.defense.status().would_block_24h, 1);
        assert_eq!(rig.defense.decision_counts_24h(SUMMARY_KEY), (0, 1));
        let status = rig.guard.status(&[]);
        assert_eq!((status.blocked_24h, status.would_block_24h), (0, 1));
        // Not repeated for the same address.
        advance(1000);
        assert!(rig.guard.tick(&peers(&[CN])).is_empty());
    }

    #[test]
    fn with_the_guardian_off_nothing_happens() {
        let rig = rig();
        guardian(&rig, GuardianMode::Off, 20);
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        assert!(rig.guard.tick(&peers(&[CN])).is_empty());
        assert!(rig.defense.status().decisions.is_empty());
        assert!(blocked(&rig).is_empty());
    }

    #[test]
    fn protected_and_trusted_addresses_are_never_blocked() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        rig.defense
            .set_allowlist(
                AllowlistConfig {
                    allowlist: vec![RU.to_owned()],
                    management: vec![],
                },
                "test",
            )
            .unwrap();
        trusted(&rig, CN);
        // Deny every country the addresses come from, and the gateway is from one of them too.
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN", "RU"]));
        let decisions = rig.guard.tick(&peers(&[CN, RU, GATEWAY, "127.0.0.1"]));
        assert!(decisions.is_empty(), "{decisions:?}");
        assert!(blocked(&rig).is_empty());
        // The untrusted neighbour from the same country is blocked.
        let decisions = rig.guard.tick(&peers(&[CN, CN2]));
        assert_eq!(decisions.len(), 1);
        assert_eq!(blocked(&rig), ["14.1.1.11/32"]);
        // In allow mode too: the trusted address of a country that is not listed stays reachable.
        let other = rig_in(tempfile::tempdir().unwrap());
        guardian(&other, GuardianMode::Active, 20);
        trusted(&other, CN);
        set(&other, policy(true, RdpCountryMode::Allow, &["US"]));
        other.guard.tick(&peers(&[CN, RU, US]));
        assert_eq!(blocked(&other), ["95.1.1.20/32"]);
    }

    #[test]
    fn private_and_reserved_addresses_are_never_candidates() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        {
            let mut known = lock(&rig.geo.known);
            for ip in ["10.1.2.3", "192.168.1.5", "169.254.1.1", "::1"] {
                known.insert(ip.parse().unwrap(), "CN".to_owned());
            }
        }
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        let decisions = rig
            .guard
            .tick(&peers(&["10.1.2.3", "192.168.1.5", "169.254.1.1", "::1"]));
        assert!(decisions.is_empty());
        assert!(blocked(&rig).is_empty());
    }

    #[test]
    fn an_unknown_country_or_a_missing_database_blocks_nothing() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        set(&rig, policy(true, RdpCountryMode::Allow, &["US"]));
        // Public but not in the database: unknown, never blocked even when only "US" is allowed.
        assert!(rig.guard.tick(&peers(&[NOWHERE])).is_empty());
        // The database goes missing or corrupt: the known ones are not judged either.
        rig.geo.ready.store(false, Ordering::SeqCst);
        assert!(rig.guard.tick(&peers(&[CN, RU])).is_empty());
        assert!(blocked(&rig).is_empty());
        assert!(rig.defense.status().decisions.is_empty());
    }

    #[test]
    fn the_circuit_breaker_is_shared_with_the_guardian() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 1);
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        let decisions = rig.guard.tick(&peers(&[CN, CN2]));
        let outcomes: Vec<&str> = decisions.iter().map(|d| d.outcome.as_str()).collect();
        assert_eq!(outcomes, ["blocked", "skipped_circuit"]);
        assert_eq!(blocked(&rig), ["14.1.1.10/32"]);
        assert!(rig.defense.status().circuit_open);
        // The refused one is retried later, not on every tick.
        advance(10);
        assert!(rig.guard.tick(&peers(&[CN2])).is_empty());
        advance(RETRY_SECS);
        assert_eq!(rig.guard.tick(&peers(&[CN2]))[0].outcome, "skipped_circuit");
        assert_eq!(blocked(&rig), ["14.1.1.10/32"]);
    }

    #[test]
    fn an_allow_policy_with_no_country_is_refused() {
        let rig = rig();
        let err = rig
            .guard
            .set_policy(policy(true, RdpCountryMode::Allow, &[]), &[], "test")
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(!rig.guard.enabled());
        // Off with an empty list, and deny with an empty list, are harmless.
        set(&rig, policy(false, RdpCountryMode::Allow, &[]));
        set(&rig, policy(true, RdpCountryMode::Deny, &[]));
    }

    #[test]
    fn an_allow_policy_that_excludes_the_operators_country_is_refused() {
        let rig = rig();
        trusted(&rig, CN);
        let connected: Vec<IpAddr> = vec![CN.parse().unwrap(), RU.parse().unwrap()];
        let err = rig
            .guard
            .set_policy(
                policy(true, RdpCountryMode::Allow, &["US"]),
                &connected,
                "test",
            )
            .unwrap_err();
        assert!(err.message.contains("CN"), "{}", err.message);
        assert!(!err.message.contains("RU"), "RU is not the operator");
        assert!(!rig.guard.enabled());
        let status = rig
            .guard
            .set_policy(
                policy(true, RdpCountryMode::Allow, &["US", "CN"]),
                &connected,
                "test",
            )
            .unwrap();
        assert!(status.policy.enabled);
        assert_eq!(status.operator_countries, ["CN"]);
        // Deny mode saves even when it names the operator's country: protected addresses stay safe.
        let denied = rig
            .guard
            .set_policy(
                policy(true, RdpCountryMode::Deny, &["CN"]),
                &connected,
                "test",
            )
            .unwrap();
        assert_eq!(denied.policy.mode, RdpCountryMode::Deny);
    }

    #[test]
    fn codes_are_validated() {
        let rig = rig();
        for bad in ["us", "USA", "U", "1A", "", "U S", "ÜS"] {
            let result =
                rig.guard
                    .set_policy(policy(false, RdpCountryMode::Deny, &[bad]), &[], "test");
            assert!(result.is_err(), "{bad:?} must be refused");
        }
        let many: Vec<String> = (0..=MAX_COUNTRIES)
            .map(|i| {
                let a = char::from(b'A' + u8::try_from(i / 26 % 26).unwrap());
                let b = char::from(b'A' + u8::try_from(i % 26).unwrap());
                format!("{a}{b}")
            })
            .collect();
        assert!(many.len() > MAX_COUNTRIES);
        let too_many = RdpCountryPolicy {
            enabled: false,
            mode: RdpCountryMode::Deny,
            countries: many,
        };
        assert!(rig.guard.set_policy(too_many, &[], "test").is_err());
        let stored = rig
            .guard
            .set_policy(
                policy(false, RdpCountryMode::Deny, &["US", "CN", "US"]),
                &[],
                "test",
            )
            .unwrap();
        assert_eq!(stored.policy.countries, ["CN", "US"], "sorted, no repeats");
    }

    #[test]
    fn the_policy_persists_and_a_corrupt_file_means_off() {
        let rig = rig();
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN", "RU"]));
        let path = rig.dir.path().join(FILE_NAME);
        assert!(path.exists());
        let again = CountryGuard::with_clock(
            Arc::clone(&rig.defense),
            Arc::clone(&rig.geo) as Arc<dyn CountrySource>,
            Some(rig.dir.path().to_path_buf()),
            clock,
        );
        assert_eq!(
            again.policy(),
            policy(true, RdpCountryMode::Deny, &["CN", "RU"])
        );

        for garbage in [
            "{ not json",
            "",
            r#"{"enabled": true, "mode": "sideways", "countries": []}"#,
            r#"{"enabled": true, "mode": "allow", "countries": []}"#,
            r#"{"enabled": true, "mode": "deny", "countries": ["cn"]}"#,
        ] {
            fs::write(&path, garbage).unwrap();
            let broken = CountryGuard::with_clock(
                Arc::clone(&rig.defense),
                Arc::clone(&rig.geo) as Arc<dyn CountrySource>,
                Some(rig.dir.path().to_path_buf()),
                clock,
            );
            assert_eq!(broken.policy(), RdpCountryPolicy::default(), "{garbage:?}");
            assert!(!broken.enabled());
        }
    }

    #[test]
    fn changing_the_policy_judges_everybody_again() {
        let rig = rig();
        guardian(&rig, GuardianMode::Active, 20);
        set(&rig, policy(true, RdpCountryMode::Deny, &["US"]));
        rig.guard.tick(&peers(&[CN]));
        assert!(blocked(&rig).is_empty());
        set(&rig, policy(true, RdpCountryMode::Deny, &["CN"]));
        rig.guard.tick(&peers(&[CN]));
        assert_eq!(blocked(&rig), ["14.1.1.10/32"]);
        // Turned off: nothing more happens.
        set(&rig, policy(false, RdpCountryMode::Deny, &["CN"]));
        assert!(rig.guard.tick(&peers(&[CN2])).is_empty());
    }

    #[test]
    fn the_status_reports_the_database_and_the_operators_countries() {
        let rig = rig();
        trusted(&rig, US);
        let connected: Vec<IpAddr> = vec![US.parse().unwrap(), CN.parse().unwrap()];
        let status = rig.guard.status(&connected);
        assert!(status.geo_ready);
        assert_eq!(status.operator_countries, ["US"]);
        rig.geo.ready.store(false, Ordering::SeqCst);
        let status = rig.guard.status(&connected);
        assert!(!status.geo_ready && status.operator_countries.is_empty());
    }
}
