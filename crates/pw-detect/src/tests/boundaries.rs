// SPDX-License-Identifier: GPL-3.0-or-later
//! Exact-threshold behaviour, window edges, clamping and presets.
//!
//! Window recap (see `Window`): at tick time `cur` (the whole second of the clock) a counter window of
//! `N` seconds covers the completed seconds `cur-N ..= cur-1`; the second in progress is excluded.

use std::net::IpAddr;

use pw_core::{PacketMeta, TCP_ACK, TCP_SYN};

use crate::testgen::*;
use crate::{AlertPhase, Config, ConnectionCounts, Engine, Preset, Window};

use super::secs;

/// Does `key` start for `source` when a fresh engine sees `packets` and ticks at `tick_ns`?
fn fires(
    config: Config,
    packets: &[PacketMeta],
    tick_ns: u64,
    key: &str,
    source: Option<IpAddr>,
) -> bool {
    let mut engine = Engine::new(config);
    for p in packets {
        engine.ingest(p);
    }
    engine
        .tick(tick_ns)
        .iter()
        .any(|a| a.phase == AlertPhase::Started && a.summary_key == key && a.source == source)
}

/// `n` packets from `ip`, spread round-robin over `span` whole seconds starting at `start_ns`.
fn spread(n: u64, start_ns: u64, span: u64, make: impl Fn(u64) -> PacketMeta) -> Vec<PacketMeta> {
    (0..n)
        .map(|i| make(start_ns + (i % span) * SECOND + i))
        .collect()
}

fn syn(ts: u64) -> PacketMeta {
    inbound_tcp(
        ts,
        ATTACKER_SYN,
        4_000 + (ts % 1000) as u16,
        443,
        TCP_SYN,
        60,
    )
}

fn syn_config(min_syn: u32) -> Config {
    let mut c = Config::default();
    c.syn_flood.min_syn = min_syn;
    c
}

#[test]
fn syn_count_exactly_at_threshold_fires_one_below_does_not() {
    let tick = T0 + secs(5) + 500_000_000;
    let at = spread(50, T0, 5, syn);
    let below = spread(49, T0, 5, syn);
    assert!(fires(
        syn_config(50),
        &at,
        tick,
        "syn_flood",
        Some(ATTACKER_SYN)
    ));
    assert!(!fires(
        syn_config(50),
        &below,
        tick,
        "syn_flood",
        Some(ATTACKER_SYN)
    ));
}

#[test]
fn syn_window_edges_are_exact() {
    let packets = spread(50, T0, 5, syn); // seconds T0 .. T0+4
    let cfg = || syn_config(50);
    let f = |tick_s: u64| {
        fires(
            cfg(),
            &packets,
            T0 + secs(tick_s) + 1,
            "syn_flood",
            Some(ATTACKER_SYN),
        )
    };
    // The second in progress is not counted: at T0+4 only seconds T0..T0+3 are complete (40 packets).
    assert!(!f(4));
    // Complete at T0+5, still inside while the oldest second (T0) is within the last 10 completed...
    for s in 5..=10 {
        assert!(f(s), "tick at +{s}");
    }
    // ...and gone one second later: second T0 left the window, 40 packets remain.
    assert!(!f(11));
    assert!(!f(40));
}

#[test]
fn one_second_window_sees_only_the_previous_second() {
    let mut cfg = syn_config(10);
    cfg.syn_flood.window = Window::S1;
    let packets: Vec<_> = (0..10).map(|i| syn(T0 + i)).collect(); // all in second T0
    let f = |tick_s: u64| {
        fires(
            cfg.clone(),
            &packets,
            T0 + secs(tick_s) + 1,
            "syn_flood",
            Some(ATTACKER_SYN),
        )
    };
    assert!(!f(0));
    assert!(f(1));
    assert!(!f(2));
}

#[test]
fn sixty_second_window_has_ten_second_granularity() {
    let mut cfg = syn_config(20);
    cfg.syn_flood.window = Window::S60;
    // All in second T0+3, which belongs to the 10 s epoch starting at T0 (T0 is a multiple of 10).
    let packets: Vec<_> = (0..20).map(|i| syn(T0 + secs(3) + i)).collect();
    let f = |tick_s: u64| {
        fires(
            cfg.clone(),
            &packets,
            T0 + secs(tick_s) + 1,
            "syn_flood",
            Some(ATTACKER_SYN),
        )
    };
    assert!(!f(9), "the epoch is still in progress");
    assert!(f(10));
    assert!(f(69));
    assert!(!f(70), "the epoch left the 6 most recent completed ones");
}

#[test]
fn syn_completion_ratio_boundary() {
    // 200 SYN need strictly fewer than 50 ACK (25 %) to count as a flood.
    let tick = T0 + secs(5) + 500_000_000;
    let acks = |n: u64| -> Vec<PacketMeta> {
        spread(n, T0, 5, |ts| {
            inbound_tcp(ts, ATTACKER_SYN, 5_000, 443, TCP_ACK, 40)
        })
    };
    let mut flood = spread(200, T0, 5, syn);
    flood.extend(acks(49));
    assert!(fires(
        Config::default(),
        &flood,
        tick,
        "syn_flood",
        Some(ATTACKER_SYN)
    ));
    let mut flood = spread(200, T0, 5, syn);
    flood.extend(acks(50));
    assert!(!fires(
        Config::default(),
        &flood,
        tick,
        "syn_flood",
        Some(ATTACKER_SYN)
    ));
}

#[test]
fn udp_and_icmp_thresholds_are_inclusive() {
    let tick = T0 + secs(5) + 500_000_000;
    let mut cfg = Config::default();
    cfg.udp_flood.min_packets = 100;
    cfg.udp_flood.min_bytes = 1_000_000;
    cfg.icmp_flood.min_packets = 30;
    let udp = |n: u64| {
        spread(n, T0, 5, |ts| {
            inbound_udp(ts, ATTACKER_UDP, 40_000, 53, 100)
        })
    };
    assert!(fires(
        cfg.clone(),
        &udp(100),
        tick,
        "udp_flood",
        Some(ATTACKER_UDP)
    ));
    assert!(!fires(
        cfg.clone(),
        &udp(99),
        tick,
        "udp_flood",
        Some(ATTACKER_UDP)
    ));
    let icmp = |n: u64| spread(n, T0, 5, |ts| inbound_icmp(ts, ATTACKER_ICMP, 84));
    assert!(fires(
        cfg.clone(),
        &icmp(30),
        tick,
        "icmp_flood",
        Some(ATTACKER_ICMP)
    ));
    assert!(!fires(
        cfg,
        &icmp(29),
        tick,
        "icmp_flood",
        Some(ATTACKER_ICMP)
    ));
}

#[test]
fn udp_byte_threshold_is_inclusive() {
    let tick = T0 + secs(5) + 500_000_000;
    let mut cfg = Config::default();
    cfg.udp_flood.min_bytes = 10_000;
    let at = spread(10, T0, 5, |ts| {
        inbound_udp(ts, ATTACKER_UDP, 40_000, 53, 1_000)
    });
    let below = spread(10, T0, 5, |ts| {
        inbound_udp(ts, ATTACKER_UDP, 40_000, 53, 999)
    });
    assert!(fires(
        cfg.clone(),
        &at,
        tick,
        "udp_flood",
        Some(ATTACKER_UDP)
    ));
    assert!(!fires(cfg, &below, tick, "udp_flood", Some(ATTACKER_UDP)));
}

#[test]
fn port_scan_thresholds_are_inclusive_and_clamped_to_the_caps() {
    let tick = T0 + secs(3);
    let scan = |n: u16| port_scan_vertical(ATTACKER_SCAN, T0, 1..=n, 1_000_000);
    assert!(fires(
        Config::default(),
        &scan(100),
        tick,
        "port_scan_vertical",
        Some(ATTACKER_SCAN)
    ));
    assert!(!fires(
        Config::default(),
        &scan(99),
        tick,
        "port_scan_vertical",
        Some(ATTACKER_SCAN)
    ));

    // A threshold above the tracker cap is clamped, so a saturated set still fires.
    let mut cfg = Config::default();
    cfg.port_scan.min_ports = 10_000;
    cfg.port_scan.min_hosts = 10_000;
    let engine = Engine::new(cfg.clone());
    assert_eq!(engine.config().port_scan.min_ports, 512);
    assert_eq!(engine.config().port_scan.min_hosts, 64);
    assert!(fires(
        cfg.clone(),
        &scan(2_000),
        tick,
        "port_scan_vertical",
        Some(ATTACKER_SCAN)
    ));
    let targets: Vec<IpAddr> = (0..=255u8).map(|n| ip4(198, 51, 100, n)).collect();
    let sweep = port_scan_horizontal(ATTACKER_SCAN, T0, &targets, 22, 1_000_000);
    assert!(fires(
        cfg,
        &sweep,
        tick,
        "port_scan_horizontal",
        Some(ATTACKER_SCAN)
    ));
}

#[test]
fn port_scan_window_is_exact_not_epoch_aligned() {
    // 100 ports all probed in second T0; visible for ages 0..=60 s.
    let packets = port_scan_vertical(ATTACKER_SCAN, T0, 1..=100, 1_000_000);
    let f = |s: u64| {
        fires(
            Config::default(),
            &packets,
            T0 + secs(s),
            "port_scan_vertical",
            Some(ATTACKER_SCAN),
        )
    };
    assert!(f(0), "the in-progress second counts for distinct sets");
    assert!(f(60));
    assert!(!f(61));
}

#[test]
fn conn_flood_snapshot_thresholds_are_inclusive() {
    let run = |concurrent: u32, new: u32| {
        let mut engine = Engine::new(Config::default());
        engine
            .observe_connection_counts(T0, [(ATTACKER_SYN, ConnectionCounts { concurrent, new })]);
        engine
            .tick(T0 + SECOND)
            .iter()
            .any(|a| a.phase == AlertPhase::Started && a.summary_key == "conn_flood")
    };
    assert!(run(250, 0));
    assert!(!run(249, 0));
    assert!(run(10, 1_000));
    assert!(!run(10, 999));
}

#[test]
fn rdp_window_is_sliding_and_inclusive_of_the_count() {
    // Ten failures over 299 s (first at T0, last at T0+299 s) are all inside (now-300, now].
    let ten = |last_gap: u64| -> Vec<LogonFailure> {
        let mut v = rdp_failures(ATTACKER_RDP, T0, 9, 10 * SECOND);
        v.push(LogonFailure {
            ip: ATTACKER_RDP,
            at_ns: T0 + last_gap,
        });
        v
    };
    let eval = |failures: Vec<LogonFailure>, tick_ns: u64| {
        let mut engine = Engine::new(Config::default());
        for f in failures {
            engine.observe_logon_failure(f.ip, f.at_ns);
        }
        engine
            .tick(tick_ns)
            .iter()
            .any(|a| a.phase == AlertPhase::Started && a.summary_key == "rdp_brute_force")
    };
    assert!(eval(ten(secs(299)), T0 + secs(299)));
    // One second later the first failure is exactly `window` old and has left.
    assert!(!eval(ten(secs(299)), T0 + secs(300)));
    // Nine failures never fire.
    assert!(!eval(
        rdp_failures(ATTACKER_RDP, T0, 9, SECOND),
        T0 + secs(20)
    ));
    assert!(eval(
        rdp_failures(ATTACKER_RDP, T0, 10, SECOND),
        T0 + secs(20)
    ));
}

#[test]
fn aggregate_threshold_and_sustain_are_inclusive() {
    let run = |permille: u64, ticks: u64| {
        let mut engine = Engine::new(Config::default());
        let mut fired = false;
        for s in 0..=ticks {
            let now = T0 + s * SECOND;
            engine.observe_inbound_bps(now, permille * 1_000_000, 1_000_000_000);
            fired |= engine
                .tick(now)
                .iter()
                .any(|a| a.summary_key == "volumetric_attack");
        }
        fired
    };
    assert!(run(900, 10), "90 % sustained for exactly 10 s");
    assert!(!run(899, 30));
    assert!(!run(900, 9));
}

#[test]
fn presets_scale_the_balanced_defaults() {
    assert_eq!(Config::preset(Preset::Balanced), Config::default());
    let (g, b, s) = (
        Config::preset(Preset::Gentle),
        Config::preset(Preset::Balanced),
        Config::preset(Preset::Strict),
    );
    assert_eq!(g.syn_flood.min_syn, 2 * b.syn_flood.min_syn);
    assert_eq!(s.syn_flood.min_syn, b.syn_flood.min_syn / 2);
    assert!(
        g.udp_flood.min_packets > b.udp_flood.min_packets
            && b.udp_flood.min_packets > s.udp_flood.min_packets
    );
    assert!(
        g.icmp_flood.min_packets > b.icmp_flood.min_packets
            && b.icmp_flood.min_packets > s.icmp_flood.min_packets
    );
    assert!(g.rdp_brute_force.min_failures > b.rdp_brute_force.min_failures);
    assert!(b.rdp_brute_force.min_failures > s.rdp_brute_force.min_failures);
    assert!(g.syn_flood.max_completion_pct < b.syn_flood.max_completion_pct);
    assert!(b.syn_flood.max_completion_pct < s.syn_flood.max_completion_pct);
    assert!(g.aggregate.min_utilization_pct > b.aggregate.min_utilization_pct);
    assert!(b.aggregate.min_utilization_pct > s.aggregate.min_utilization_pct);
    for c in [g, b, s] {
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.clone().sanitized(), c);
    }
}

#[test]
fn validate_reports_and_sanitize_repairs_bad_values() {
    let mut c = Config::default();
    c.syn_flood.min_syn = 0;
    c.syn_flood.max_completion_pct = 400;
    c.port_scan.min_ports = 5_000;
    c.conn_flood.window = Window::S60;
    c.limits.max_sources = 0;
    assert!(c.validate().is_err());
    let fixed = c.sanitized();
    assert_eq!(fixed.validate(), Ok(()));
    assert_eq!(fixed.syn_flood.min_syn, 1);
    assert_eq!(fixed.syn_flood.max_completion_pct, 100);
    assert_eq!(fixed.port_scan.min_ports, 512);
    assert_eq!(fixed.conn_flood.window, Window::S10);
    assert!(fixed.limits.max_sources >= 16);
}
