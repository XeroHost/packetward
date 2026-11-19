// SPDX-License-Identifier: GPL-3.0-or-later
//! Detector configuration, severities, windows and the `Gentle` / `Balanced` / `Strict` presets.
//!
//! Every threshold in this module is a **count inside the detector's window** (not a rate), so a
//! boundary is unambiguous: a window that holds exactly `min_*` events fires, one fewer does not.
//! The defaults are the `Balanced` preset and are deliberately conservative: a busy, legitimate
//! server (thousands of clients, large downloads, normal SYN rates) must stay silent.
//!
//! [`Config::sanitized`] (applied by `Engine::new`) clamps out-of-range values instead of failing;
//! [`Config::validate`] reports them, for settings UIs.

use serde::{Deserialize, Serialize};

use crate::scan::{HOST_CAP, PORT_CAP};

/// Alert severity, ordered `Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Raise by `steps` levels, saturating at `Critical`.
    pub fn raise(self, steps: u8) -> Severity {
        let rank = (self as u8).saturating_add(steps).min(3);
        match rank {
            0 => Severity::Low,
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A sliding counter window. Counter windows cover completed seconds only:
///
/// * `S1`  — the last completed second (`cur-1`).
/// * `S10` — the last 10 completed seconds (`cur-10 ..= cur-1`).
/// * `S60` — the last 6 completed, 10-second-aligned epochs (60 s, up to 10 s of extra latency
///   because the epoch in progress is excluded).
///
/// `cur` is the second of the engine clock at evaluation time. The in-progress second is never part
/// of a counter window, so rates are never under-counted by a partial second and the detection
/// latency is at most one tick. Distinct-port/host sets are the one exception: they also include the
/// in-progress second (they only ever make a scan *more* visible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Window {
    S1,
    S10,
    S60,
}

impl Window {
    pub fn secs(self) -> u32 {
        match self {
            Window::S1 => 1,
            Window::S10 => 10,
            Window::S60 => 60,
        }
    }

    pub(crate) fn index(self) -> usize {
        match self {
            Window::S1 => 0,
            Window::S10 => 1,
            Window::S60 => 2,
        }
    }
}

/// Scales every threshold of [`Config::default`] (which is `Balanced`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    /// Fewer alerts: thresholds x2, stricter "low completion" ratios, 95 % link utilisation.
    Gentle,
    /// The defaults.
    Balanced,
    /// More alerts: thresholds x0.5, looser ratios, 80 % link utilisation.
    Strict,
}

/// Why a [`Config`] is not acceptable as written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("`{0}` is out of range")]
    OutOfRange(&'static str),
}

/// `SynFlood`: many SYNs from one source that rarely complete the handshake.
///
/// Per source: fires when `syn >= min_syn` and `ack * 100 < syn * max_completion_pct`, where `syn`
/// counts inbound SYN-only packets and `ack` inbound ACK-bearing, non-SYN, non-RST TCP packets in
/// the window (handshake completions *and* data ACKs: a real client always has at least one per SYN).
///
/// A source that is also port scanning (`PortScan` condition true) is reported as a scan only,
/// unless its SYN count alone is already `escalate_factor` times the threshold.
///
/// Distributed (unattributed, `source = None`): the SYN volume *not already attributed* to a
/// per-source `SynFlood` alert is compared with `global_min_syn` (0 disables) and
/// `global_max_completion_pct`. Legitimate ACKs of the whole server dilute the global ratio, so the
/// default is "fewer ACKs than SYNs", which only fires when handshakes clearly go unanswered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SynFloodConfig {
    pub enabled: bool,
    pub window: Window,
    pub min_syn: u32,
    pub max_completion_pct: u32,
    pub severity: Severity,
    /// Severity is raised one level each time the metric reaches another `escalate_factor` x.
    pub escalate_factor: u32,
    pub cooldown_secs: u32,
    pub global_min_syn: u64,
    pub global_max_completion_pct: u32,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window: Window::S10,
            // 20 SYN/s sustained from one address with < 25 % completion.
            min_syn: 200,
            max_completion_pct: 25,
            severity: Severity::High,
            escalate_factor: 10,
            cooldown_secs: 60,
            // 1000 unattributed SYN/s.
            global_min_syn: 10_000,
            global_max_completion_pct: 100,
        }
    }
}

/// `UdpFlood`: inbound UDP volume per source (fires on packets OR bytes) or in aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpFloodConfig {
    pub enabled: bool,
    pub window: Window,
    pub min_packets: u32,
    pub min_bytes: u64,
    pub severity: Severity,
    pub escalate_factor: u32,
    pub cooldown_secs: u32,
    /// Unattributed UDP packets in the window (0 disables).
    pub global_min_packets: u64,
    /// Unattributed UDP bytes in the window (0 disables).
    pub global_min_bytes: u64,
}

impl Default for UdpFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window: Window::S10,
            // 10 000 pps or 200 Mbit/s from one address. RDP's UDP transport and game servers
            // stay below this; a trusted RDP client above it still alerts, flagged `protected`.
            min_packets: 100_000,
            min_bytes: 250_000_000,
            severity: Severity::Medium,
            escalate_factor: 10,
            cooldown_secs: 60,
            // 100 000 pps / 1 Gbit/s unattributed.
            global_min_packets: 1_000_000,
            global_min_bytes: 1_250_000_000,
        }
    }
}

/// `IcmpFlood`: inbound ICMP/ICMPv6 packets per source or in aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IcmpFloodConfig {
    pub enabled: bool,
    pub window: Window,
    pub min_packets: u32,
    pub severity: Severity,
    pub escalate_factor: u32,
    pub cooldown_secs: u32,
    /// Unattributed ICMP packets in the window (0 disables).
    pub global_min_packets: u64,
}

impl Default for IcmpFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window: Window::S10,
            // 300 pps from one address (a normal ping is 1 pps).
            min_packets: 3_000,
            severity: Severity::Medium,
            escalate_factor: 10,
            cooldown_secs: 60,
            global_min_packets: 500_000,
        }
    }
}

/// `PortScan`: distinct destination **ports** (vertical scan, `port_scan_vertical`) or distinct
/// destination **addresses** (horizontal sweep, `port_scan_horizontal`) probed by one source.
///
/// Only probes count: inbound TCP SYN-only, TCP without SYN/ACK/RST (NULL/FIN/Xmas) and UDP whose
/// source port is >= 1024 (replies from DNS/NTP/... carry a well-known source port and are not
/// probes). Multicast/broadcast destinations are ignored. The sets are exact up to
/// `PORT_CAP` = 512 ports / `HOST_CAP` = 64 hosts per source; the thresholds are clamped to those
/// caps so a saturated set always means "fires".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortScanConfig {
    pub enabled: bool,
    pub window: Window,
    pub min_ports: u32,
    pub min_hosts: u32,
    pub severity: Severity,
    pub escalate_factor: u32,
    pub cooldown_secs: u32,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // Exact sliding set: a scan of >= 100 ports in 60 s (1.7 ports/s) is caught however it
            // is paced inside the window; slower scans are not detected (documented limitation).
            window: Window::S60,
            min_ports: 100,
            min_hosts: 32,
            // Internet background scanning is constant, so this is informational by default.
            severity: Severity::Low,
            escalate_factor: 4,
            // The 60 s window already keeps the incident open for a minute after the last probe.
            cooldown_secs: 60,
        }
    }
}

/// `ConnFlood`: too many TCP connections from one address.
///
/// Inputs: `observe_connection_counts` (works without capture) and, when capture is running,
/// the inbound SYN count of sources whose handshakes DO complete (the complement of `SynFlood`).
/// Fires when `concurrent >= max_concurrent` (snapshot not older than `snapshot_ttl_secs`) or when
/// `new >= min_new` in the window (`S60` is treated as `S10`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnFloodConfig {
    pub enabled: bool,
    pub window: Window,
    pub max_concurrent: u32,
    pub min_new: u32,
    pub snapshot_ttl_secs: u32,
    pub severity: Severity,
    pub escalate_factor: u32,
    pub cooldown_secs: u32,
}

impl Default for ConnFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window: Window::S10,
            max_concurrent: 250,
            // 100 new connections/s from one address.
            min_new: 1_000,
            snapshot_ttl_secs: 15,
            severity: Severity::Medium,
            escalate_factor: 4,
            cooldown_secs: 60,
        }
    }
}

/// `RdpBruteForce`: `min_failures` failed logons from one address within `window_secs`
/// (events come from Security 4625, parsed elsewhere). The window is sliding and exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RdpBruteForceConfig {
    pub enabled: bool,
    pub window_secs: u32,
    pub min_failures: u32,
    pub severity: Severity,
    pub escalate_factor: u32,
    pub cooldown_secs: u32,
}

impl Default for RdpBruteForceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // A user who mistypes a password a few times never reaches 10 in 5 minutes.
            window_secs: 300,
            min_failures: 10,
            severity: Severity::Medium,
            escalate_factor: 5,
            // The 300 s window already keeps the incident open after the last failure.
            cooldown_secs: 60,
        }
    }
}

/// `Aggregate`: total inbound bandwidth near link capacity, a "volumetric attack, upstream
/// mitigation required" notice that is never attributed to a source (`source = None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AggregateConfig {
    pub enabled: bool,
    pub min_utilization_pct: u32,
    pub critical_utilization_pct: u32,
    /// Utilisation must stay at or above the threshold for this long.
    pub sustain_secs: u32,
    /// A bandwidth sample older than this no longer counts.
    pub stale_secs: u32,
    pub severity: Severity,
    pub cooldown_secs: u32,
}

impl Default for AggregateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_utilization_pct: 90,
            critical_utilization_pct: 98,
            sustain_secs: 10,
            stale_secs: 10,
            severity: Severity::High,
            cooldown_secs: 60,
        }
    }
}

/// Hard bounds on the engine's memory. See the crate docs for the eviction policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Tracked source addresses (~0.7 KB each: ~35 MB at the default).
    pub max_sources: usize,
    /// Sources with an expanded distinct port/host set (~4.6 KB each).
    pub max_scan_trackers: usize,
    /// Open incidents (one per detector and source).
    pub max_incidents: usize,
    /// Remote addresses tracked from connection snapshots.
    pub max_conn_sources: usize,
    /// Addresses tracked for failed logons.
    pub max_logon_sources: usize,
    /// New (`Started`) alerts per tick; the rest wait for the next tick.
    pub max_new_alerts_per_tick: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sources: 50_000,
            max_scan_trackers: 2_048,
            max_incidents: 10_000,
            max_conn_sources: 20_000,
            max_logon_sources: 10_000,
            max_new_alerts_per_tick: 256,
        }
    }
}

/// The whole engine configuration. `Default` is the `Balanced` preset.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub syn_flood: SynFloodConfig,
    pub udp_flood: UdpFloodConfig,
    pub icmp_flood: IcmpFloodConfig,
    pub port_scan: PortScanConfig,
    pub conn_flood: ConnFloodConfig,
    pub rdp_brute_force: RdpBruteForceConfig,
    pub aggregate: AggregateConfig,
    pub limits: Limits,
}

fn scale32(v: u32, num: u32, den: u32) -> u32 {
    let scaled = u64::from(v) * u64::from(num) / u64::from(den);
    u32::try_from(scaled.max(1)).unwrap_or(u32::MAX)
}

fn scale64(v: u64, num: u64, den: u64) -> u64 {
    (v.saturating_mul(num) / den).max(1)
}

/// Keep `0` ("disabled") as `0`.
fn scale64_keep_zero(v: u64, num: u64, den: u64) -> u64 {
    if v == 0 {
        0
    } else {
        scale64(v, num, den)
    }
}

impl Config {
    /// Build a preset. `Balanced` equals `Config::default()`.
    pub fn preset(preset: Preset) -> Config {
        let mut c = Config::default();
        let (num, den) = match preset {
            Preset::Balanced => return c,
            Preset::Gentle => (2u32, 1u32),
            Preset::Strict => (1, 2),
        };
        let (n64, d64) = (u64::from(num), u64::from(den));
        c.syn_flood.min_syn = scale32(c.syn_flood.min_syn, num, den);
        c.syn_flood.global_min_syn = scale64_keep_zero(c.syn_flood.global_min_syn, n64, d64);
        c.udp_flood.min_packets = scale32(c.udp_flood.min_packets, num, den);
        c.udp_flood.min_bytes = scale64(c.udp_flood.min_bytes, n64, d64);
        c.udp_flood.global_min_packets =
            scale64_keep_zero(c.udp_flood.global_min_packets, n64, d64);
        c.udp_flood.global_min_bytes = scale64_keep_zero(c.udp_flood.global_min_bytes, n64, d64);
        c.icmp_flood.min_packets = scale32(c.icmp_flood.min_packets, num, den);
        c.icmp_flood.global_min_packets =
            scale64_keep_zero(c.icmp_flood.global_min_packets, n64, d64);
        c.port_scan.min_ports = scale32(c.port_scan.min_ports, num, den);
        c.port_scan.min_hosts = scale32(c.port_scan.min_hosts, num, den);
        c.conn_flood.max_concurrent = scale32(c.conn_flood.max_concurrent, num, den);
        c.conn_flood.min_new = scale32(c.conn_flood.min_new, num, den);
        c.rdp_brute_force.min_failures = scale32(c.rdp_brute_force.min_failures, num, den);
        match preset {
            Preset::Gentle => {
                c.syn_flood.max_completion_pct = 15;
                c.aggregate.min_utilization_pct = 95;
                c.aggregate.critical_utilization_pct = 99;
            }
            _ => {
                c.syn_flood.max_completion_pct = 40;
                c.aggregate.min_utilization_pct = 80;
                c.aggregate.critical_utilization_pct = 95;
            }
        }
        c.sanitized()
    }

    /// Clamp every value into its valid range (see [`Config::validate`]).
    pub fn sanitized(mut self) -> Config {
        fn at_least(v: &mut u32, min: u32) {
            *v = (*v).max(min);
        }
        fn pct(v: &mut u32, min: u32) {
            *v = (*v).clamp(min, 100);
        }
        let s = &mut self.syn_flood;
        at_least(&mut s.min_syn, 1);
        pct(&mut s.max_completion_pct, 0);
        pct(&mut s.global_max_completion_pct, 0);
        at_least(&mut s.escalate_factor, 2);
        at_least(&mut s.cooldown_secs, 1);

        let u = &mut self.udp_flood;
        at_least(&mut u.min_packets, 1);
        u.min_bytes = u.min_bytes.max(1);
        at_least(&mut u.escalate_factor, 2);
        at_least(&mut u.cooldown_secs, 1);

        let i = &mut self.icmp_flood;
        at_least(&mut i.min_packets, 1);
        at_least(&mut i.escalate_factor, 2);
        at_least(&mut i.cooldown_secs, 1);

        let p = &mut self.port_scan;
        p.min_ports = p.min_ports.clamp(1, PORT_CAP as u32);
        p.min_hosts = p.min_hosts.clamp(1, HOST_CAP as u32);
        at_least(&mut p.escalate_factor, 2);
        at_least(&mut p.cooldown_secs, 1);

        let c = &mut self.conn_flood;
        at_least(&mut c.max_concurrent, 1);
        at_least(&mut c.min_new, 1);
        at_least(&mut c.snapshot_ttl_secs, 1);
        at_least(&mut c.escalate_factor, 2);
        at_least(&mut c.cooldown_secs, 1);
        if c.window == Window::S60 {
            c.window = Window::S10;
        }

        let r = &mut self.rdp_brute_force;
        at_least(&mut r.min_failures, 1);
        at_least(&mut r.window_secs, 1);
        r.window_secs = r.window_secs.min(86_400);
        at_least(&mut r.escalate_factor, 2);
        at_least(&mut r.cooldown_secs, 1);

        let a = &mut self.aggregate;
        pct(&mut a.min_utilization_pct, 1);
        a.critical_utilization_pct = a.critical_utilization_pct.clamp(a.min_utilization_pct, 100);
        at_least(&mut a.sustain_secs, 1);
        at_least(&mut a.stale_secs, 1);
        at_least(&mut a.cooldown_secs, 1);

        let l = &mut self.limits;
        l.max_sources = l.max_sources.max(16);
        l.max_scan_trackers = l.max_scan_trackers.max(1);
        l.max_incidents = l.max_incidents.max(16);
        l.max_conn_sources = l.max_conn_sources.max(16);
        l.max_logon_sources = l.max_logon_sources.max(16);
        l.max_new_alerts_per_tick = l.max_new_alerts_per_tick.max(1);
        self
    }

    /// `Ok` when [`Config::sanitized`] would not change anything.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let fixed = self.clone().sanitized();
        macro_rules! same {
            ($($path:ident).+) => {
                if self.$($path).+ != fixed.$($path).+ {
                    return Err(ConfigError::OutOfRange(stringify!($($path).+)));
                }
            };
        }
        same!(syn_flood.min_syn);
        same!(syn_flood.max_completion_pct);
        same!(syn_flood.global_max_completion_pct);
        same!(syn_flood.escalate_factor);
        same!(syn_flood.cooldown_secs);
        same!(udp_flood.min_packets);
        same!(udp_flood.min_bytes);
        same!(udp_flood.escalate_factor);
        same!(udp_flood.cooldown_secs);
        same!(icmp_flood.min_packets);
        same!(icmp_flood.escalate_factor);
        same!(icmp_flood.cooldown_secs);
        same!(port_scan.min_ports);
        same!(port_scan.min_hosts);
        same!(port_scan.escalate_factor);
        same!(port_scan.cooldown_secs);
        same!(conn_flood.max_concurrent);
        same!(conn_flood.min_new);
        same!(conn_flood.snapshot_ttl_secs);
        same!(conn_flood.window);
        same!(conn_flood.escalate_factor);
        same!(conn_flood.cooldown_secs);
        same!(rdp_brute_force.min_failures);
        same!(rdp_brute_force.window_secs);
        same!(rdp_brute_force.escalate_factor);
        same!(rdp_brute_force.cooldown_secs);
        same!(aggregate.min_utilization_pct);
        same!(aggregate.critical_utilization_pct);
        same!(aggregate.sustain_secs);
        same!(aggregate.stale_secs);
        same!(aggregate.cooldown_secs);
        same!(limits.max_sources);
        same!(limits.max_scan_trackers);
        same!(limits.max_incidents);
        same!(limits.max_conn_sources);
        same!(limits.max_logon_sources);
        same!(limits.max_new_alerts_per_tick);
        Ok(())
    }
}
