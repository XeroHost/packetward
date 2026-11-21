// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The detectors: pure functions from window totals to findings.
//!
//! A *finding* is "this condition holds right now"; the incident layer in `engine.rs` turns findings
//! into deduplicated alerts.

use std::net::IpAddr;

use crate::alert::{DetectorKind, Metric};
use crate::config::{Config, Severity, Window};
use crate::engine::Source;
use crate::scan::Trackers;
use crate::wheel::Totals;

/// A condition that holds at this tick.
#[derive(Debug)]
pub(crate) struct Finding {
    pub kind: DetectorKind,
    /// Summary key; also identifies the incident together with `source`.
    pub key: &'static str,
    pub source: Option<IpAddr>,
    pub severity: Severity,
    pub window_secs: u32,
    pub cooldown_secs: u32,
    /// The metric used to pick the peak and to break ties.
    pub primary: u64,
    pub metrics: Vec<Metric>,
}

/// Volume already attributed to a per-source alert this tick; the distributed (unattributed)
/// detectors only look at what remains.
#[derive(Debug, Default)]
pub(crate) struct Flagged {
    pub syn: u64,
    pub udp: u64,
    pub udp_bytes: u64,
    pub icmp: u64,
}

/// How many times `value` has reached another `factor` x of `threshold` (0..=3).
pub(crate) fn level(value: u64, threshold: u64, factor: u32) -> u8 {
    let mut n = 0u8;
    let mut t = threshold.max(1);
    while n < 3 {
        t = t.saturating_mul(u64::from(factor));
        if value >= t {
            n += 1;
        } else {
            break;
        }
    }
    n
}

pub(crate) fn permille(num: u64, den: u64) -> u64 {
    num.saturating_mul(1000).checked_div(den).unwrap_or(0)
}

fn m(key: &'static str, value: u64) -> Metric {
    Metric::new(key, value)
}

/// Evaluate every per-source detector on one source.
pub(crate) fn evaluate_source(
    cfg: &Config,
    ip: IpAddr,
    src: &Source,
    trackers: &Trackers,
    cur: u64,
    out: &mut Vec<Finding>,
    flagged: &mut Flagged,
) {
    let mut cache: [Option<Totals>; 3] = [None; 3];
    let mut totals =
        |w: Window| -> Totals { *cache[w.index()].get_or_insert_with(|| src.totals(w, cur)) };

    // The distinct port/host sets, needed by PortScan and to tell a scan from a SYN flood.
    let (ports, hosts) = if cfg.port_scan.enabled {
        src.probes
            .distinct(cur, cfg.port_scan.window.secs(), trackers)
    } else {
        (0, 0)
    };
    let scanning = cfg.port_scan.enabled
        && (ports >= cfg.port_scan.min_ports || hosts >= cfg.port_scan.min_hosts);

    // SynFlood: many SYNs, few completions. A source that is port scanning sends SYNs that never
    // complete too; that is a scan, not a flood, unless the rate alone is already a flood
    // (`escalate_factor` times the threshold). The volume stays attributed to the source either way.
    let c = &cfg.syn_flood;
    if c.enabled {
        let t = totals(c.window);
        if t.syn >= u64::from(c.min_syn)
            && t.ack.saturating_mul(100) < t.syn.saturating_mul(u64::from(c.max_completion_pct))
        {
            flagged.syn += t.syn;
            let lvl = level(t.syn, u64::from(c.min_syn), c.escalate_factor);
            if !(scanning && lvl == 0) {
                out.push(Finding {
                    kind: DetectorKind::SynFlood,
                    key: "syn_flood",
                    source: Some(ip),
                    severity: c.severity.raise(lvl),
                    window_secs: c.window.secs(),
                    cooldown_secs: c.cooldown_secs,
                    primary: t.syn,
                    metrics: vec![
                        m("syn", t.syn),
                        m("ack", t.ack),
                        m("completion_permille", permille(t.ack, t.syn)),
                    ],
                });
            }
        }
    }

    // UdpFlood: packets OR bytes.
    let c = &cfg.udp_flood;
    if c.enabled {
        let t = totals(c.window);
        if t.udp >= u64::from(c.min_packets) || t.udp_bytes >= c.min_bytes {
            flagged.udp += t.udp;
            flagged.udp_bytes += t.udp_bytes;
            let lvl = level(t.udp, u64::from(c.min_packets), c.escalate_factor).max(level(
                t.udp_bytes,
                c.min_bytes,
                c.escalate_factor,
            ));
            out.push(Finding {
                kind: DetectorKind::UdpFlood,
                key: "udp_flood",
                source: Some(ip),
                severity: c.severity.raise(lvl),
                window_secs: c.window.secs(),
                cooldown_secs: c.cooldown_secs,
                primary: t.udp,
                metrics: vec![m("packets", t.udp), m("bytes", t.udp_bytes)],
            });
        }
    }

    // IcmpFlood.
    let c = &cfg.icmp_flood;
    if c.enabled {
        let t = totals(c.window);
        if t.icmp >= u64::from(c.min_packets) {
            flagged.icmp += t.icmp;
            out.push(Finding {
                kind: DetectorKind::IcmpFlood,
                key: "icmp_flood",
                source: Some(ip),
                severity: c.severity.raise(level(
                    t.icmp,
                    u64::from(c.min_packets),
                    c.escalate_factor,
                )),
                window_secs: c.window.secs(),
                cooldown_secs: c.cooldown_secs,
                primary: t.icmp,
                metrics: vec![m("packets", t.icmp)],
            });
        }
    }

    // PortScan: exact distinct sets.
    let c = &cfg.port_scan;
    if c.enabled {
        if ports >= c.min_ports {
            out.push(Finding {
                kind: DetectorKind::PortScan,
                key: "port_scan_vertical",
                source: Some(ip),
                severity: c.severity.raise(level(
                    u64::from(ports),
                    u64::from(c.min_ports),
                    c.escalate_factor,
                )),
                window_secs: c.window.secs(),
                cooldown_secs: c.cooldown_secs,
                primary: u64::from(ports),
                metrics: vec![
                    m("distinct_ports", u64::from(ports)),
                    m("distinct_hosts", u64::from(hosts)),
                ],
            });
        }
        if hosts >= c.min_hosts {
            out.push(Finding {
                kind: DetectorKind::PortScan,
                key: "port_scan_horizontal",
                source: Some(ip),
                severity: c.severity.raise(level(
                    u64::from(hosts),
                    u64::from(c.min_hosts),
                    c.escalate_factor,
                )),
                window_secs: c.window.secs(),
                cooldown_secs: c.cooldown_secs,
                primary: u64::from(hosts),
                metrics: vec![
                    m("distinct_hosts", u64::from(hosts)),
                    m("distinct_ports", u64::from(ports)),
                ],
            });
        }
    }

    // ConnFlood from capture: new connections that DO complete their handshake (the complement of
    // SynFlood, so one attack does not raise both).
    let c = &cfg.conn_flood;
    if c.enabled {
        let t = totals(c.window);
        let sc = &cfg.syn_flood;
        let healthy =
            t.ack.saturating_mul(100) >= t.syn.saturating_mul(u64::from(sc.max_completion_pct));
        if t.syn >= u64::from(c.min_new) && healthy {
            out.push(Finding {
                kind: DetectorKind::ConnFlood,
                key: "conn_flood",
                source: Some(ip),
                severity: c
                    .severity
                    .raise(level(t.syn, u64::from(c.min_new), c.escalate_factor)),
                window_secs: c.window.secs(),
                cooldown_secs: c.cooldown_secs,
                primary: t.syn,
                metrics: vec![m("new_connections", t.syn)],
            });
        }
    }
}
