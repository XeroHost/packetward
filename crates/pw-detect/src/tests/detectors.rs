// SPDX-License-Identifier: GPL-3.0-or-later
//! Every detector fires on its attack and the whole set stays quiet on healthy traffic.

use std::net::IpAddr;

use crate::testgen::*;
use crate::{AlertPhase, Config, DetectorKind, Engine, Preset, Severity};

use super::{has_started, run, started};

const END: u64 = T0 + 600 * SECOND;

#[test]
fn normal_traffic_raises_nothing_for_any_detector() {
    let packets = normal_web(7, T0, 20, 4_000);
    assert!(
        packets.len() > 200_000,
        "the fixture must be busy: {}",
        packets.len()
    );
    // A cooldown's worth of extra ticks after the traffic ends, so an alert could also end.
    for preset in [Preset::Gentle, Preset::Balanced, Preset::Strict] {
        let alerts = run(Config::preset(preset), packets.clone(), &[], T0, END);
        assert!(alerts.is_empty(), "{preset:?} raised {alerts:#?}");
    }
}

#[test]
fn syn_flood_from_one_source_gives_exactly_one_alert_then_ends() {
    let packets = syn_flood(ATTACKER_SYN, T0, 15, 100);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(alerts.len(), 2, "{alerts:#?}");
    let a = &alerts[0];
    assert_eq!(a.phase, AlertPhase::Started);
    assert_eq!(a.kind, DetectorKind::SynFlood);
    assert_eq!(a.summary_key, "syn_flood");
    assert_eq!(a.source, Some(ATTACKER_SYN));
    assert_eq!(a.severity, Severity::High);
    assert!(a.metric("syn").is_some_and(|v| v >= 200));
    assert_eq!(a.metric("ack"), Some(0));
    assert_eq!(a.window_secs, 10);
    let end = &alerts[1];
    assert_eq!((end.phase, end.id), (AlertPhase::Ended, a.id));
    assert!(end.last_seen_ns > a.first_seen_ns);
}

#[test]
fn spoofed_syn_flood_is_reported_without_a_source() {
    let packets = spoofed_syn_flood(3, T0, 15, 5_000);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("syn_flood_distributed", None)],
        "{alerts:#?}"
    );
    let a = &alerts[0];
    assert_eq!(a.kind, DetectorKind::SynFlood);
    assert!(!a.protected);
    assert!(a.metric("syn_unattributed").is_some_and(|v| v >= 10_000));
}

#[test]
fn udp_flood_from_one_source() {
    let packets = udp_flood(ATTACKER_UDP, T0, 15, 20_000, 1000);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("udp_flood", Some(ATTACKER_UDP))],
        "{alerts:#?}"
    );
    assert_eq!(alerts[0].kind, DetectorKind::UdpFlood);
    assert_eq!(alerts[0].severity, Severity::Medium);
}

#[test]
fn udp_flood_by_bytes_alone() {
    // 2000 pps of 9000-byte datagrams: 18 MB/s = 180 MB / 10 s (< 250 MB), then 4000 pps.
    let packets = udp_flood(ATTACKER_UDP, T0, 15, 4_000, 9_000);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert!(
        has_started(&alerts, "udp_flood", Some(ATTACKER_UDP)),
        "{alerts:#?}"
    );
}

#[test]
fn spoofed_udp_flood_is_unattributed() {
    let mut config = Config::default();
    config.udp_flood.global_min_packets = 30_000;
    config.udp_flood.global_min_bytes = 0;
    let packets: Vec<_> = spoofed_udp_iter(5, T0, 10_000, 120_000).collect();
    let alerts = run(config, packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("udp_flood_distributed", None)],
        "{alerts:#?}"
    );
}

#[test]
fn icmp_flood_from_one_source() {
    let packets = icmp_flood(ATTACKER_ICMP, T0, 15, 500);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("icmp_flood", Some(ATTACKER_ICMP))],
        "{alerts:#?}"
    );
    assert_eq!(alerts[0].severity, Severity::Medium);
}

#[test]
fn icmp_flood_from_many_sources_is_unattributed() {
    let mut config = Config::default();
    config.icmp_flood.global_min_packets = 20_000;
    let packets: Vec<_> = (0..60_000u64)
        .map(|i| inbound_icmp(T0 + i * SECOND / 6_000, client_ip((i % 5_000) as u32), 84))
        .collect();
    let alerts = run(config, packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("icmp_flood_distributed", None)],
        "{alerts:#?}"
    );
}

#[test]
fn vertical_port_scan() {
    let packets = port_scan_vertical(ATTACKER_SCAN, T0, 1..=300, SECOND / 50);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("port_scan_vertical", Some(ATTACKER_SCAN))],
        "{alerts:#?}"
    );
    assert_eq!(alerts[0].kind, DetectorKind::PortScan);
    assert_eq!(alerts[0].severity, Severity::Low);
    assert!(alerts[0].metric("distinct_ports").is_some_and(|v| v >= 100));
}

#[test]
fn a_scan_fast_enough_to_be_a_flood_raises_both() {
    // 500 SYN/s over 2000 distinct ports: 5000 SYN per 10 s, 25x the SynFlood threshold.
    let packets = port_scan_vertical(ATTACKER_SCAN, T0, 1..=3000, SECOND / 500);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert!(
        has_started(&alerts, "port_scan_vertical", Some(ATTACKER_SCAN)),
        "{alerts:#?}"
    );
    assert!(
        has_started(&alerts, "syn_flood", Some(ATTACKER_SCAN)),
        "{alerts:#?}"
    );
}

#[test]
fn a_fast_horizontal_sweep_is_one_alert_not_a_syn_flood_too() {
    // 50 SYN/s (500 per 10 s) over 500 hosts: the host set saturates at its cap, still >= 32.
    let targets: Vec<IpAddr> = (0..500u32).map(|n| client_ip(5_000_000 + n)).collect();
    let packets = port_scan_horizontal(ATTACKER_SCAN, T0, &targets, 3389, SECOND / 50);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("port_scan_horizontal", Some(ATTACKER_SCAN))],
        "{alerts:#?}"
    );
}

#[test]
fn horizontal_port_scan() {
    let targets: Vec<IpAddr> = (1..=60u8).map(|n| ip4(198, 51, 100, n)).collect();
    let packets = port_scan_horizontal(ATTACKER_SCAN, T0, &targets, 22, SECOND / 10);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("port_scan_horizontal", Some(ATTACKER_SCAN))],
        "{alerts:#?}"
    );
}

#[test]
fn stealth_and_udp_scans_count_as_scans() {
    for packets in [
        stealth_scan(ATTACKER_SCAN, T0, 1..=300, SECOND / 50, 0),
        stealth_scan(ATTACKER_SCAN, T0, 1..=300, SECOND / 50, pw_core::TCP_FIN),
        udp_port_scan(ATTACKER_SCAN, T0, 1..=300, SECOND / 50),
    ] {
        let alerts = run(Config::default(), packets, &[], T0, END);
        assert!(
            has_started(&alerts, "port_scan_vertical", Some(ATTACKER_SCAN)),
            "{alerts:#?}"
        );
    }
}

#[test]
fn slow_scan_is_caught_when_it_fits_the_window_and_missed_below_it() {
    // 2 ports/s: 120 ports per 60 s window.
    let caught = slow_scan(ATTACKER_SCAN, T0, 200, SECOND / 2);
    let alerts = run(Config::default(), caught, &[], T0, END);
    assert!(
        has_started(&alerts, "port_scan_vertical", Some(ATTACKER_SCAN)),
        "{alerts:#?}"
    );

    // 1 port/s is at most 61 live entries in any 60 s window: below the default 100 (documented).
    let missed = slow_scan(ATTACKER_SCAN, T0, 300, SECOND);
    let alerts = run(Config::default(), missed, &[], T0, END);
    assert!(alerts.is_empty(), "{alerts:#?}");
}

#[test]
fn a_connection_flood_that_completes_handshakes_is_conn_flood_not_syn_flood() {
    let packets = conn_flood_capture(ATTACKER_SYN, T0, 15, 150);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        started(&alerts),
        vec![("conn_flood", Some(ATTACKER_SYN))],
        "{alerts:#?}"
    );
}

#[test]
fn conn_flood_from_netstat_snapshots_without_capture() {
    use crate::ConnectionCounts;
    let mut engine = Engine::new(Config::default());
    let mut alerts = Vec::new();
    for s in 0..15u64 {
        let now = T0 + s * SECOND;
        engine.observe_connection_counts(
            now,
            [
                (
                    ATTACKER_SYN,
                    ConnectionCounts {
                        concurrent: 300,
                        new: 0,
                    },
                ),
                // A NAT with many connections, below the threshold.
                (
                    ip4(192, 0, 2, 77),
                    ConnectionCounts {
                        concurrent: 120,
                        new: 5,
                    },
                ),
            ],
        );
        alerts.extend(engine.tick(now + 1));
    }
    assert_eq!(
        started(&alerts),
        vec![("conn_flood", Some(ATTACKER_SYN))],
        "{alerts:#?}"
    );
    assert_eq!(alerts[0].metric("concurrent_connections"), Some(300));
    assert_eq!(
        engine.stats().packets_inbound,
        0,
        "capture was never involved"
    );
}

#[test]
fn conn_flood_by_new_connection_rate_from_netstat() {
    use crate::ConnectionCounts;
    let mut engine = Engine::new(Config::default());
    let mut alerts = Vec::new();
    for s in 0..15u64 {
        let now = T0 + s * SECOND;
        engine.observe_connection_counts(
            now,
            [(
                ATTACKER_SYN,
                ConnectionCounts {
                    concurrent: 10,
                    new: 150,
                },
            )],
        );
        alerts.extend(engine.tick(now + 1));
    }
    assert!(
        has_started(&alerts, "conn_flood", Some(ATTACKER_SYN)),
        "{alerts:#?}"
    );
}

#[test]
fn stale_connection_snapshots_do_not_keep_alerting() {
    use crate::ConnectionCounts;
    let mut engine = Engine::new(Config::default());
    engine.observe_connection_counts(
        T0,
        [(
            ATTACKER_SYN,
            ConnectionCounts {
                concurrent: 300,
                new: 0,
            },
        )],
    );
    assert!(!engine.tick(T0 + SECOND).is_empty());
    // No further snapshot: after the 15 s TTL the condition is false and, after the cooldown, ends.
    let mut ended = false;
    for s in 2..200u64 {
        ended |= engine
            .tick(T0 + s * SECOND)
            .iter()
            .any(|a| a.phase == AlertPhase::Ended);
    }
    assert!(ended);
    assert_eq!(engine.open_incidents(), 0);
}

#[test]
fn rdp_brute_force_from_failed_logons() {
    let logons = rdp_failures(ATTACKER_RDP, T0, 40, 2 * SECOND);
    let alerts = run(Config::default(), Vec::new(), &logons, T0, END);
    assert_eq!(
        started(&alerts),
        vec![("rdp_brute_force", Some(ATTACKER_RDP))],
        "{alerts:#?}"
    );
    let a = &alerts[0];
    assert_eq!(
        (a.kind, a.severity, a.window_secs),
        (DetectorKind::RdpBruteForce, Severity::Medium, 300)
    );
    assert!(a.metric("failures").is_some_and(|v| v >= 10));
}

#[test]
fn a_user_who_mistypes_a_few_times_is_not_a_brute_force() {
    let mut logons = rdp_failures(RDP_USER, T0, 3, 5 * SECOND);
    // Nine failures spread over two minutes: still below ten in five minutes.
    logons.extend(rdp_failures(ip4(192, 0, 2, 98), T0, 9, 15 * SECOND));
    logons.sort_by_key(|l| l.at_ns);
    let alerts = run(Config::default(), Vec::new(), &logons, T0, END);
    assert!(alerts.is_empty(), "{alerts:#?}");
}

#[test]
fn aggregate_volumetric_attack_is_never_attributed() {
    let gbit = 1_000_000_000u64;
    let mut engine = Engine::new(Config::default());
    let mut alerts = Vec::new();
    for s in 0..30u64 {
        let now = T0 + s * SECOND;
        engine.observe_inbound_bps(now, 950_000_000, gbit);
        alerts.extend(engine.tick(now));
    }
    assert_eq!(
        started(&alerts),
        vec![("volumetric_attack", None)],
        "{alerts:#?}"
    );
    let a = &alerts[0];
    assert_eq!(
        (a.kind, a.severity, a.source),
        (DetectorKind::Aggregate, Severity::High, None)
    );
    assert_eq!(a.metric("utilization_permille"), Some(950));
    assert!(!a.protected);

    // Saturated link: critical.
    let mut engine = Engine::new(Config::default());
    let mut alerts = Vec::new();
    for s in 0..30u64 {
        let now = T0 + s * SECOND;
        engine.observe_inbound_bps(now, 995_000_000, gbit);
        alerts.extend(engine.tick(now));
    }
    assert_eq!(alerts[0].severity, Severity::Critical);
}

#[test]
fn aggregate_needs_sustained_known_link_and_fresh_samples() {
    let gbit = 1_000_000_000u64;
    // Below the threshold.
    let mut engine = Engine::new(Config::default());
    for s in 0..60u64 {
        let now = T0 + s * SECOND;
        engine.observe_inbound_bps(now, 800_000_000, gbit);
        assert!(engine.tick(now).is_empty());
    }
    // A short spike (5 s) is not sustained.
    let mut engine = Engine::new(Config::default());
    for s in 0..60u64 {
        let now = T0 + s * SECOND;
        engine.observe_inbound_bps(now, if s < 5 { 990_000_000 } else { 100_000_000 }, gbit);
        assert!(engine.tick(now).is_empty());
    }
    // Unknown link speed never alerts.
    let mut engine = Engine::new(Config::default());
    for s in 0..60u64 {
        let now = T0 + s * SECOND;
        engine.observe_inbound_bps(now, 990_000_000, 0);
        assert!(engine.tick(now).is_empty());
    }
    // Samples stop arriving: the alert ends instead of sticking.
    let mut engine = Engine::new(Config::default());
    let mut alerts = Vec::new();
    for s in 0..15u64 {
        let now = T0 + s * SECOND;
        engine.observe_inbound_bps(now, 990_000_000, gbit);
        alerts.extend(engine.tick(now));
    }
    for s in 15..200u64 {
        alerts.extend(engine.tick(T0 + s * SECOND));
    }
    assert!(alerts.iter().any(|a| a.phase == AlertPhase::Ended));
    assert_eq!(engine.open_incidents(), 0);
}

#[test]
fn mixed_attacks_inside_healthy_traffic_are_each_found_and_nothing_else() {
    let (packets, logons) = mixed(11, T0, 30, 3_000);
    let alerts = run(Config::default(), packets, &logons, T0, END);
    let mut got = started(&alerts);
    got.sort();
    let mut want = vec![
        ("syn_flood", Some(ATTACKER_SYN)),
        ("udp_flood", Some(ATTACKER_UDP)),
        ("icmp_flood", Some(ATTACKER_ICMP)),
        ("port_scan_vertical", Some(ATTACKER_SCAN)),
        ("rdp_brute_force", Some(ATTACKER_RDP)),
    ];
    want.sort();
    assert_eq!(got, want, "{alerts:#?}");
    // Every incident also ended, with the same id.
    for a in alerts.iter().filter(|a| a.phase == AlertPhase::Started) {
        assert!(
            alerts
                .iter()
                .any(|e| e.phase == AlertPhase::Ended && e.id == a.id),
            "no end for {a:#?}"
        );
    }
}

#[test]
fn the_same_scenario_gives_identical_alerts_every_run() {
    let (packets, logons) = mixed(11, T0, 30, 1_000);
    let first = run(Config::default(), packets.clone(), &logons, T0, END);
    for _ in 0..3 {
        // New engines get new hash seeds: the output must not depend on them.
        assert_eq!(
            run(Config::default(), packets.clone(), &logons, T0, END),
            first
        );
    }
    assert!(!first.is_empty());
}
