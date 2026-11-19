// SPDX-License-Identifier: GPL-3.0-or-later
//! The detection engine: ingest, observations, tick and the incident (dedup) layer.

use std::cmp::Reverse;
use std::collections::hash_map::Entry as MapEntry;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use pw_core::{CidrSet, Direction, PacketMeta};
use serde::Serialize;

use crate::alert::{Alert, AlertPhase, DetectorKind, Metric};
use crate::config::{Config, Severity, Window};
use crate::eval::{evaluate_source, level, permille, Finding, Flagged};
use crate::scan::{host_hash, Probes, Touch, Trackers};
use crate::wheel::{
    CoarseWheel, Delta, FineWheel, GlobalCounters, NewCounter, SrcCounters, Totals, Wheel,
};

/// Nanoseconds per second (the unit of every timestamp in this crate).
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// A packet timestamp this far ahead of the engine clock is treated as a clock anomaly and ignored
/// (it would otherwise expire every window and poison the clock). `tick` is authoritative and may
/// always move the clock forward.
const MAX_FORWARD_JUMP_NS: u64 = 3_600 * NS_PER_SEC;
/// `tick` going backwards by more than this re-bases the clock (the system clock was set back).
const REBASE_BACKWARD_NS: u64 = 3_600 * NS_PER_SEC;
/// A source with no packet for this long has nothing left in any window.
const IDLE_SECS: u64 = 75;
/// Connection snapshot rows below this (both concurrent and new) are not tracked.
const CONN_TRACK_FLOOR: u32 = 4;

/// One remote address in a connection snapshot (from netstat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCounts {
    /// TCP connections to/from the address right now.
    pub concurrent: u32,
    /// Connections that were not in the previous snapshot (computed by the caller; 0 if unknown).
    pub new: u32,
}

/// Counters for diagnostics and the UI. Plain numbers, never reset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EngineStats {
    pub packets_inbound: u64,
    pub packets_outbound: u64,
    /// Inbound packets of sources that could not be tracked because the table was full.
    pub packets_untracked: u64,
    pub sources_evicted: u64,
    pub scan_tracker_exhausted: u64,
    pub time_regressions: u64,
    pub time_anomalies: u64,
    pub time_rebases: u64,
    pub alerts_emitted: u64,
    /// New incidents deferred to a later tick (per-tick cap) or refused (incident cap).
    pub alerts_deferred: u64,
    pub incidents_refused: u64,
}

pub(crate) struct Source {
    last_sec: u64,
    fine: FineWheel<SrcCounters>,
    coarse: CoarseWheel<SrcCounters>,
    pub(crate) probes: Probes,
}

impl Source {
    fn new() -> Self {
        Self {
            last_sec: 0,
            fine: Wheel::new(),
            coarse: Wheel::new(),
            probes: Probes::new(),
        }
    }

    pub(crate) fn totals(&self, w: Window, cur: u64) -> Totals {
        match w {
            Window::S1 => self.fine.totals(cur, 1),
            Window::S10 => self.fine.totals(cur, 10),
            Window::S60 => self.coarse.totals(cur, 6),
        }
    }
}

struct ConnState {
    concurrent: u32,
    obs_ns: u64,
    last_new_sec: u64,
    new_hist: FineWheel<NewCounter>,
}

struct Logon {
    times: VecDeque<u64>,
    last_ns: u64,
}

#[derive(Default)]
struct AggState {
    have: bool,
    at_ns: u64,
    bps: u64,
    link_bps: u64,
    util_permille: u64,
    since_ns: Option<u64>,
}

struct Incident {
    id: u64,
    kind: DetectorKind,
    key: &'static str,
    source: Option<IpAddr>,
    window_secs: u32,
    cooldown_secs: u32,
    first_seen_ns: u64,
    last_met_ns: u64,
    severity: Severity,
    peak_primary: u64,
    peak_metrics: Vec<Metric>,
}

/// The detection engine. See the crate docs for the model.
pub struct Engine {
    cfg: Config,
    protected: CidrSet,
    clock: u64,
    clock_set: bool,
    sources: HashMap<IpAddr, Source>,
    trackers: Trackers,
    global_fine: FineWheel<GlobalCounters>,
    global_coarse: CoarseWheel<GlobalCounters>,
    conns: HashMap<IpAddr, ConnState>,
    logons: HashMap<IpAddr, Logon>,
    agg: AggState,
    incidents: HashMap<(&'static str, Option<IpAddr>), Incident>,
    next_id: u64,
    stats: EngineStats,
    findings: Vec<Finding>,
}

impl Engine {
    /// Build an engine. The configuration is [sanitized](Config::sanitized).
    pub fn new(config: Config) -> Self {
        let cfg = config.sanitized();
        Self {
            trackers: Trackers::new(cfg.limits.max_scan_trackers),
            sources: HashMap::with_capacity(cfg.limits.max_sources.min(1024)),
            cfg,
            protected: CidrSet::new(),
            clock: 0,
            clock_set: false,
            global_fine: Wheel::new(),
            global_coarse: Wheel::new(),
            conns: HashMap::new(),
            logons: HashMap::new(),
            agg: AggState::default(),
            incidents: HashMap::new(),
            next_id: 1,
            stats: EngineStats::default(),
            findings: Vec::new(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Replace the configuration, keeping all counters and open incidents.
    pub fn set_config(&mut self, config: Config) {
        self.cfg = config.sanitized();
        self.trackers.set_max(self.cfg.limits.max_scan_trackers);
    }

    /// The set used to compute `Alert::protected` (RDP trust set, allowlist, gateway, DNS, ...).
    /// Replaceable at any time; affects alerts emitted from now on.
    pub fn set_protected(&mut self, protected: CidrSet) {
        self.protected = protected;
    }

    pub fn stats(&self) -> EngineStats {
        self.stats
    }

    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    pub fn scan_trackers_in_use(&self) -> usize {
        self.trackers.in_use()
    }

    pub fn open_incidents(&self) -> usize {
        self.incidents.len()
    }

    /// Remote addresses currently tracked from connection snapshots.
    pub fn tracked_connection_sources(&self) -> usize {
        self.conns.len()
    }

    /// Addresses currently tracked for failed logons.
    pub fn tracked_logon_sources(&self) -> usize {
        self.logons.len()
    }

    // ---- clock -------------------------------------------------------------------------------

    /// The engine clock after folding in a packet/observation timestamp.
    fn clock_for_event(&mut self, ts: u64) -> u64 {
        if !self.clock_set {
            self.clock_set = true;
            self.clock = ts;
            return ts;
        }
        if ts >= self.clock {
            if ts - self.clock > MAX_FORWARD_JUMP_NS {
                self.stats.time_anomalies += 1;
                return self.clock;
            }
            self.clock = ts;
            ts
        } else {
            self.stats.time_regressions += 1;
            self.clock
        }
    }

    fn clock_for_tick(&mut self, now: u64) {
        if !self.clock_set {
            self.clock_set = true;
            self.clock = now;
        } else if now >= self.clock {
            self.clock = now;
        } else if self.clock - now > REBASE_BACKWARD_NS {
            self.clock = now;
            self.stats.time_rebases += 1;
        } else {
            self.stats.time_regressions += 1;
        }
    }

    // ---- inputs ------------------------------------------------------------------------------

    /// Feed one packet. Hot path: one hash lookup, a few counter increments, no allocation after
    /// warm-up (table growth and the first promotion of a scan tracker allocate, bounded by
    /// [`Limits`](crate::Limits)). Outbound packets only update machine-wide counters.
    pub fn ingest(&mut self, p: &PacketMeta) {
        let ts = self.clock_for_event(p.timestamp_ns);
        let sec = ts / NS_PER_SEC;
        if p.direction == Direction::Outbound {
            self.stats.packets_outbound += 1;
            self.global_fine.at(sec).add_outbound(p);
            self.global_coarse.at(sec).add_outbound(p);
            return;
        }
        self.stats.packets_inbound += 1;
        let (delta, probe) = Delta::classify(p);
        self.global_fine.at(sec).add_inbound(&delta);
        self.global_coarse.at(sec).add_inbound(&delta);

        let ip = p.src.to_canonical();
        let full = self.sources.len() >= self.cfg.limits.max_sources;
        let src = match self.sources.entry(ip) {
            MapEntry::Occupied(o) => o.into_mut(),
            MapEntry::Vacant(v) => {
                if full {
                    self.stats.packets_untracked += 1;
                    return;
                }
                v.insert(Source::new())
            }
        };
        src.last_sec = sec;
        src.fine.at(sec).add(&delta);
        src.coarse.at(sec).add(&delta);
        if probe && !is_multicast_or_broadcast(p.dst) {
            let touch = src
                .probes
                .touch(sec, p.dst_port, host_hash(p.dst), &mut self.trackers);
            if matches!(touch, Touch::Exhausted) {
                self.stats.scan_tracker_exhausted += 1;
            }
        }
    }

    /// Replace the per-remote-address TCP connection snapshot (from netstat; works without capture).
    /// Addresses missing from `rows` are considered to have no connections. Rows below a small noise
    /// floor are ignored. Duplicate rows for one address add up.
    pub fn observe_connection_counts<I>(&mut self, now_ns: u64, rows: I)
    where
        I: IntoIterator<Item = (IpAddr, ConnectionCounts)>,
    {
        let now = self.clock_for_event(now_ns);
        let sec = now / NS_PER_SEC;
        for st in self.conns.values_mut() {
            st.concurrent = 0;
        }
        let cap = self.cfg.limits.max_conn_sources;
        for (ip, c) in rows {
            let ip = ip.to_canonical();
            if c.concurrent < CONN_TRACK_FLOOR
                && c.new < CONN_TRACK_FLOOR
                && !self.conns.contains_key(&ip)
            {
                continue;
            }
            let full = self.conns.len() >= cap;
            let st = match self.conns.entry(ip) {
                MapEntry::Occupied(o) => o.into_mut(),
                MapEntry::Vacant(v) => {
                    if full {
                        continue;
                    }
                    v.insert(ConnState {
                        concurrent: 0,
                        obs_ns: now,
                        last_new_sec: sec,
                        new_hist: Wheel::new(),
                    })
                }
            };
            st.concurrent = st.concurrent.saturating_add(c.concurrent);
            st.obs_ns = now;
            if c.new > 0 {
                let cell = st.new_hist.at(sec);
                cell.0 = cell.0.saturating_add(c.new);
                st.last_new_sec = sec;
            }
        }
    }

    /// Report the machine-wide inbound bandwidth and the link speed (both bits per second), for the
    /// `Aggregate` detector. A `link_speed_bps` of 0 (unknown) never raises an alert.
    pub fn observe_inbound_bps(&mut self, now_ns: u64, total_bps: u64, link_speed_bps: u64) {
        let now = self.clock_for_event(now_ns);
        let util = if link_speed_bps == 0 {
            0
        } else {
            u64::try_from(u128::from(total_bps) * 1000 / u128::from(link_speed_bps))
                .unwrap_or(u64::MAX)
        };
        let threshold = u64::from(self.cfg.aggregate.min_utilization_pct) * 10;
        let a = &mut self.agg;
        a.have = true;
        a.at_ns = now;
        a.bps = total_bps;
        a.link_bps = link_speed_bps;
        a.util_permille = util;
        if link_speed_bps > 0 && util >= threshold {
            a.since_ns.get_or_insert(now);
        } else {
            a.since_ns = None;
        }
    }

    /// Record one failed logon (Security 4625) from `ip` at `at_ns` for `RdpBruteForce`.
    /// Only feed live events: failures older than the detector window are ignored at the next tick.
    pub fn observe_logon_failure(&mut self, ip: IpAddr, at_ns: u64) {
        let c = &self.cfg.rdp_brute_force;
        if !c.enabled {
            return;
        }
        let window_ns = u64::from(c.window_secs) * NS_PER_SEC;
        let per_ip_cap = (u64::from(c.min_failures)
            .saturating_mul(u64::from(c.escalate_factor))
            .saturating_mul(u64::from(c.escalate_factor))
            .saturating_add(1))
        .clamp(16, 4096) as usize;
        let _ = self.clock_for_event(at_ns);
        // A late event keeps its own time; a future-dated one is pinned to the clock.
        let at = at_ns.min(self.clock);
        let ip = ip.to_canonical();

        if !self.logons.contains_key(&ip) && self.logons.len() >= self.cfg.limits.max_logon_sources
        {
            // Evict the address whose latest failure is the oldest (ties: lowest address).
            let victim = self.logons.iter().map(|(k, v)| (v.last_ns, *k)).min();
            if let Some((_, k)) = victim {
                self.logons.remove(&k);
            }
        }
        let l = self.logons.entry(ip).or_insert_with(|| Logon {
            times: VecDeque::new(),
            last_ns: 0,
        });
        let at = at.max(l.last_ns);
        l.last_ns = at;
        l.times.push_back(at);
        while l
            .times
            .front()
            .is_some_and(|t| t.saturating_add(window_ns) <= at)
        {
            l.times.pop_front();
        }
        while l.times.len() > per_ip_cap {
            l.times.pop_front();
        }
    }

    // ---- tick --------------------------------------------------------------------------------

    /// Evaluate every detector at `now_ns` and return the alerts to publish (new, escalated, ended),
    /// in a deterministic order. Call about once per second; `now_ns` must use the same clock as the
    /// packet timestamps (nanoseconds since the Unix epoch). A `now_ns` slightly in the past is
    /// ignored (the engine clock never goes back); one more than an hour in the past re-bases it.
    pub fn tick(&mut self, now_ns: u64) -> Vec<Alert> {
        self.clock_for_tick(now_ns);
        let now = self.clock;
        let cur = now / NS_PER_SEC;
        let mut findings = std::mem::take(&mut self.findings);
        findings.clear();

        let flagged = self.evaluate_sources(cur, &mut findings);
        self.evaluate_global(cur, &flagged, &mut findings);
        self.evaluate_conns(cur, now, &mut findings);
        self.evaluate_logons(now, &mut findings);
        self.evaluate_aggregate(now, &mut findings);
        self.enforce_source_cap(cur);
        self.apply_findings(now, findings)
    }

    fn evaluate_sources(&mut self, cur: u64, out: &mut Vec<Finding>) -> Flagged {
        let Engine {
            cfg,
            sources,
            trackers,
            stats,
            ..
        } = self;
        let mut flagged = Flagged::default();
        sources.retain(|ip, src| {
            if cur > src.last_sec.saturating_add(IDLE_SECS) {
                src.probes.release(trackers);
                stats.sources_evicted += 1;
                return false;
            }
            evaluate_source(cfg, *ip, src, trackers, cur, out, &mut flagged);
            src.probes.compact(cur, trackers);
            true
        });
        flagged
    }

    fn global_totals(&self, w: Window, cur: u64) -> Totals {
        match w {
            Window::S1 => self.global_fine.totals(cur, 1),
            Window::S10 => self.global_fine.totals(cur, 10),
            Window::S60 => self.global_coarse.totals(cur, 6),
        }
    }

    fn evaluate_global(&self, cur: u64, flagged: &Flagged, out: &mut Vec<Finding>) {
        let m = Metric::new;

        let c = &self.cfg.syn_flood;
        if c.enabled && c.global_min_syn > 0 {
            let t = self.global_totals(c.window, cur);
            let rest = t.syn.saturating_sub(flagged.syn);
            if rest >= c.global_min_syn
                && t.ack.saturating_mul(100)
                    < rest.saturating_mul(u64::from(c.global_max_completion_pct))
            {
                out.push(Finding {
                    kind: DetectorKind::SynFlood,
                    key: "syn_flood_distributed",
                    source: None,
                    severity: c
                        .severity
                        .raise(level(rest, c.global_min_syn, c.escalate_factor)),
                    window_secs: c.window.secs(),
                    cooldown_secs: c.cooldown_secs,
                    primary: rest,
                    metrics: vec![
                        m("syn_unattributed", rest),
                        m("syn_total", t.syn),
                        m("ack_total", t.ack),
                        m("synack_out", t.synack_out),
                        m("completion_permille", permille(t.ack, rest)),
                    ],
                });
            }
        }

        let c = &self.cfg.udp_flood;
        if c.enabled && (c.global_min_packets > 0 || c.global_min_bytes > 0) {
            let t = self.global_totals(c.window, cur);
            let pk = t.udp.saturating_sub(flagged.udp);
            let by = t.udp_bytes.saturating_sub(flagged.udp_bytes);
            let hit_pk = c.global_min_packets > 0 && pk >= c.global_min_packets;
            let hit_by = c.global_min_bytes > 0 && by >= c.global_min_bytes;
            if hit_pk || hit_by {
                let mut lvl = 0;
                if hit_pk {
                    lvl = lvl.max(level(pk, c.global_min_packets, c.escalate_factor));
                }
                if hit_by {
                    lvl = lvl.max(level(by, c.global_min_bytes, c.escalate_factor));
                }
                out.push(Finding {
                    kind: DetectorKind::UdpFlood,
                    key: "udp_flood_distributed",
                    source: None,
                    severity: c.severity.raise(lvl),
                    window_secs: c.window.secs(),
                    cooldown_secs: c.cooldown_secs,
                    primary: pk,
                    metrics: vec![m("packets_unattributed", pk), m("bytes_unattributed", by)],
                });
            }
        }

        let c = &self.cfg.icmp_flood;
        if c.enabled && c.global_min_packets > 0 {
            let t = self.global_totals(c.window, cur);
            let pk = t.icmp.saturating_sub(flagged.icmp);
            if pk >= c.global_min_packets {
                out.push(Finding {
                    kind: DetectorKind::IcmpFlood,
                    key: "icmp_flood_distributed",
                    source: None,
                    severity: c
                        .severity
                        .raise(level(pk, c.global_min_packets, c.escalate_factor)),
                    window_secs: c.window.secs(),
                    cooldown_secs: c.cooldown_secs,
                    primary: pk,
                    metrics: vec![m("packets_unattributed", pk)],
                });
            }
        }
    }

    fn evaluate_conns(&mut self, cur: u64, now: u64, out: &mut Vec<Finding>) {
        let c = self.cfg.conn_flood.clone();
        self.conns.retain(|ip, st| {
            let fresh =
                now.saturating_sub(st.obs_ns) <= u64::from(c.snapshot_ttl_secs) * NS_PER_SEC;
            // A snapshot older than the TTL says nothing about the present.
            let concurrent = if fresh { u64::from(st.concurrent) } else { 0 };
            if concurrent == 0 && cur > st.last_new_sec.saturating_add(IDLE_SECS) {
                return false;
            }
            if !c.enabled {
                return true;
            }
            let epochs = if c.window == Window::S1 { 1 } else { 10 };
            let new = st.new_hist.totals(cur, epochs).syn;
            let hit_c = concurrent >= u64::from(c.max_concurrent);
            let hit_n = new >= u64::from(c.min_new);
            if hit_c || hit_n {
                let mut lvl = 0;
                if hit_c {
                    lvl = lvl.max(level(
                        concurrent,
                        u64::from(c.max_concurrent),
                        c.escalate_factor,
                    ));
                }
                if hit_n {
                    lvl = lvl.max(level(new, u64::from(c.min_new), c.escalate_factor));
                }
                out.push(Finding {
                    kind: DetectorKind::ConnFlood,
                    key: "conn_flood",
                    source: Some(*ip),
                    severity: c.severity.raise(lvl),
                    window_secs: c.window.secs().min(10),
                    cooldown_secs: c.cooldown_secs,
                    primary: concurrent.max(new),
                    metrics: vec![
                        Metric::new("concurrent_connections", concurrent),
                        Metric::new("new_connections", new),
                    ],
                });
            }
            true
        });
    }

    fn evaluate_logons(&mut self, now: u64, out: &mut Vec<Finding>) {
        let c = self.cfg.rdp_brute_force.clone();
        let window_ns = u64::from(c.window_secs) * NS_PER_SEC;
        self.logons.retain(|ip, l| {
            while l
                .times
                .front()
                .is_some_and(|t| t.saturating_add(window_ns) <= now)
            {
                l.times.pop_front();
            }
            if l.times.is_empty() {
                return false;
            }
            let n = l.times.len() as u64;
            if c.enabled && n >= u64::from(c.min_failures) {
                out.push(Finding {
                    kind: DetectorKind::RdpBruteForce,
                    key: "rdp_brute_force",
                    source: Some(*ip),
                    severity: c.severity.raise(level(
                        n,
                        u64::from(c.min_failures),
                        c.escalate_factor,
                    )),
                    window_secs: c.window_secs,
                    cooldown_secs: c.cooldown_secs,
                    primary: n,
                    metrics: vec![Metric::new("failures", n)],
                });
            }
            true
        });
    }

    fn evaluate_aggregate(&self, now: u64, out: &mut Vec<Finding>) {
        let c = &self.cfg.aggregate;
        let a = &self.agg;
        if !c.enabled || !a.have {
            return;
        }
        let fresh = now.saturating_sub(a.at_ns) <= u64::from(c.stale_secs) * NS_PER_SEC;
        let Some(since) = a.since_ns else { return };
        let sustained = now.saturating_sub(since) / NS_PER_SEC;
        if !fresh || sustained < u64::from(c.sustain_secs) {
            return;
        }
        let severity = if a.util_permille >= u64::from(c.critical_utilization_pct) * 10 {
            Severity::Critical
        } else {
            c.severity
        };
        out.push(Finding {
            kind: DetectorKind::Aggregate,
            key: "volumetric_attack",
            source: None,
            severity,
            window_secs: c.sustain_secs,
            cooldown_secs: c.cooldown_secs,
            primary: a.util_permille,
            metrics: vec![
                Metric::new("inbound_bps", a.bps),
                Metric::new("link_bps", a.link_bps),
                Metric::new("utilization_permille", a.util_permille),
                Metric::new("sustained_secs", sustained),
            ],
        });
    }

    /// Keep the source table below its cap: when it is more than 75 % full, drop the quietest
    /// sources (fewest packets in the last ~10 s, ties by address) down to 75 %. Loud sources (real
    /// attackers) rank last and survive; the tracker of each victim returns to the pool.
    fn enforce_source_cap(&mut self, cur: u64) {
        let cap = self.cfg.limits.max_sources;
        let soft = cap - cap / 4;
        if self.sources.len() <= soft {
            return;
        }
        let mut ranked: Vec<(u64, IpAddr)> = self
            .sources
            .iter()
            // Evaluate as if one second later so the in-progress second counts.
            .map(|(ip, s)| (s.fine.totals(cur + 1, 10).pkts, *ip))
            .collect();
        ranked.sort_unstable();
        let excess = self.sources.len() - soft;
        for (_, ip) in ranked.into_iter().take(excess) {
            if let Some(mut s) = self.sources.remove(&ip) {
                s.probes.release(&mut self.trackers);
                self.stats.sources_evicted += 1;
            }
        }
        tracing::debug!(
            tracked = self.sources.len(),
            "pw-detect: source table trimmed"
        );
    }

    // ---- incidents ---------------------------------------------------------------------------

    fn make_alert(&self, inc: &Incident, phase: AlertPhase) -> Alert {
        Alert {
            id: inc.id,
            phase,
            kind: inc.kind,
            severity: inc.severity,
            source: inc.source,
            summary_key: inc.key,
            metrics: inc.peak_metrics.clone(),
            window_secs: inc.window_secs,
            first_seen_ns: inc.first_seen_ns,
            last_seen_ns: inc.last_met_ns,
            protected: inc.source.is_some_and(|ip| self.protected.contains(ip)),
        }
    }

    fn apply_findings(&mut self, now: u64, mut findings: Vec<Finding>) -> Vec<Alert> {
        // Total orders only: nothing here may depend on hash-map iteration order.
        findings.sort_by(|a, b| {
            (a.key, a.source, Reverse(a.primary)).cmp(&(b.key, b.source, Reverse(b.primary)))
        });
        findings.dedup_by(|b, a| a.key == b.key && a.source == b.source);
        findings.sort_by(|a, b| {
            (Reverse(a.severity), a.kind, a.key, a.source).cmp(&(
                Reverse(b.severity),
                b.kind,
                b.key,
                b.source,
            ))
        });

        let mut alerts = Vec::new();
        let mut started = 0usize;
        for f in findings.drain(..) {
            let key = (f.key, f.source);
            if let Some(inc) = self.incidents.get_mut(&key) {
                inc.last_met_ns = now;
                if f.primary > inc.peak_primary {
                    inc.peak_primary = f.primary;
                    inc.peak_metrics = f.metrics;
                    inc.window_secs = f.window_secs;
                }
                inc.cooldown_secs = f.cooldown_secs;
                if f.severity > inc.severity {
                    inc.severity = f.severity;
                    let snapshot = self
                        .incidents
                        .get(&key)
                        .map(|i| self.make_alert(i, AlertPhase::Escalated));
                    if let Some(alert) = snapshot {
                        tracing::debug!(
                            id = alert.id,
                            key = alert.summary_key,
                            "pw-detect: alert escalated"
                        );
                        alerts.push(alert);
                    }
                }
                continue;
            }
            if self.incidents.len() >= self.cfg.limits.max_incidents {
                self.stats.incidents_refused += 1;
                continue;
            }
            if started >= self.cfg.limits.max_new_alerts_per_tick {
                self.stats.alerts_deferred += 1;
                continue;
            }
            started += 1;
            let inc = Incident {
                id: self.next_id,
                kind: f.kind,
                key: f.key,
                source: f.source,
                window_secs: f.window_secs,
                cooldown_secs: f.cooldown_secs,
                first_seen_ns: now,
                last_met_ns: now,
                severity: f.severity,
                peak_primary: f.primary,
                peak_metrics: f.metrics,
            };
            self.next_id += 1;
            let alert = self.make_alert(&inc, AlertPhase::Started);
            tracing::debug!(
                id = alert.id,
                key = alert.summary_key,
                "pw-detect: alert started"
            );
            alerts.push(alert);
            self.incidents.insert(key, inc);
        }
        self.findings = findings;

        // Ended: the condition has been false for the whole cooldown.
        let mut ended: Vec<(u64, (&'static str, Option<IpAddr>))> = self
            .incidents
            .iter()
            .filter(|(_, i)| {
                now.saturating_sub(i.last_met_ns) >= u64::from(i.cooldown_secs) * NS_PER_SEC
            })
            .map(|(k, i)| (i.id, *k))
            .collect();
        ended.sort_unstable();
        for (_, key) in ended {
            if let Some(inc) = self.incidents.remove(&key) {
                let alert = self.make_alert(&inc, AlertPhase::Ended);
                tracing::debug!(
                    id = alert.id,
                    key = alert.summary_key,
                    "pw-detect: alert ended"
                );
                alerts.push(alert);
            }
        }
        self.stats.alerts_emitted += alerts.len() as u64;
        alerts
    }
}

fn is_multicast_or_broadcast(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}
