// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Odd clocks: epoch zero, time going backwards, huge jumps, extreme values. None may panic or
//! poison the engine.

use crate::testgen::*;
use crate::{Config, Engine};

use super::{has_started, run, secs};

const END: u64 = 600 * SECOND;

#[test]
fn detection_works_from_epoch_zero() {
    let alerts = run(
        Config::default(),
        syn_flood(ATTACKER_SYN, 0, 15, 100),
        &[],
        0,
        END,
    );
    assert!(
        has_started(&alerts, "syn_flood", Some(ATTACKER_SYN)),
        "{alerts:#?}"
    );
    let alerts = run(
        Config::default(),
        Vec::new(),
        &rdp_failures(ATTACKER_RDP, 0, 20, SECOND),
        0,
        END,
    );
    assert!(
        has_started(&alerts, "rdp_brute_force", Some(ATTACKER_RDP)),
        "{alerts:#?}"
    );
}

#[test]
fn time_going_backwards_does_not_panic_or_lose_the_clock() {
    let mut engine = Engine::new(Config::default());
    engine.ingest(&inbound_tcp(
        T0 + secs(100),
        ATTACKER_SYN,
        1,
        443,
        pw_core::TCP_SYN,
        60,
    ));
    // A packet from 100 s earlier, then a tick in the past: both ignored by the clock.
    engine.ingest(&inbound_tcp(T0, ATTACKER_SYN, 2, 443, pw_core::TCP_SYN, 60));
    assert!(engine.tick(T0 + secs(50)).is_empty());
    let stats = engine.stats();
    assert_eq!(stats.time_regressions, 2);
    assert_eq!(stats.packets_inbound, 2);
    // Forward again works.
    assert!(engine.tick(T0 + secs(101)).is_empty());
    engine.observe_logon_failure(ATTACKER_RDP, T0);
    engine.observe_inbound_bps(T0, 1, 2);
    engine.observe_connection_counts(T0, []);
}

#[test]
fn a_clock_set_far_back_rebases_instead_of_freezing_detection() {
    let mut engine = Engine::new(Config::default());
    let _ = engine.tick(T0 + secs(10_000));
    // The administrator moved the clock back two hours.
    let back = T0 + secs(10_000) - secs(7_200);
    let _ = engine.tick(back);
    assert_eq!(engine.stats().time_rebases, 1);
    let alerts = replay(
        &mut engine,
        syn_flood(ATTACKER_SYN, back, 15, 100),
        &[],
        back,
        back + secs(40),
    );
    assert!(
        has_started(&alerts, "syn_flood", Some(ATTACKER_SYN)),
        "{alerts:#?}"
    );
}

#[test]
fn one_absurd_future_timestamp_does_not_poison_the_clock() {
    let mut engine = Engine::new(Config::default());
    engine.ingest(&inbound_tcp(T0, ATTACKER_SYN, 1, 443, pw_core::TCP_SYN, 60));
    let ten_years = T0 + 10 * 365 * 86_400 * SECOND;
    engine.ingest(&inbound_tcp(
        ten_years,
        ATTACKER_SYN,
        2,
        443,
        pw_core::TCP_SYN,
        60,
    ));
    engine.observe_logon_failure(ATTACKER_RDP, ten_years);
    assert_eq!(engine.stats().time_anomalies, 2);
    // The normal stream keeps working afterwards.
    let alerts = replay(
        &mut engine,
        syn_flood(ATTACKER_SYN, T0, 15, 100),
        &[],
        T0,
        T0 + secs(40),
    );
    assert!(
        has_started(&alerts, "syn_flood", Some(ATTACKER_SYN)),
        "{alerts:#?}"
    );
}

#[test]
fn extreme_values_do_not_overflow() {
    let mut engine = Engine::new(Config::default());
    engine.ingest(&inbound_tcp(
        u64::MAX,
        ATTACKER_SYN,
        1,
        443,
        pw_core::TCP_SYN,
        u32::MAX,
    ));
    engine.ingest(&inbound_udp(u64::MAX, ATTACKER_UDP, 40_000, 53, u32::MAX));
    engine.observe_logon_failure(ATTACKER_RDP, u64::MAX);
    engine.observe_inbound_bps(u64::MAX, u64::MAX, 1);
    engine.observe_connection_counts(
        u64::MAX,
        [(
            ATTACKER_SYN,
            crate::ConnectionCounts {
                concurrent: u32::MAX,
                new: u32::MAX,
            },
        )],
    );
    let _ = engine.tick(u64::MAX);
    let _ = engine.tick(0);
    let _ = engine.tick(u64::MAX);

    // The largest packet sizes saturate counters instead of wrapping.
    let mut engine = Engine::new(Config::default());
    for i in 0..20u64 {
        engine.ingest(&inbound_udp(T0 + i, ATTACKER_UDP, 40_000, 53, u32::MAX));
    }
    let alerts = engine.tick(T0 + secs(1));
    assert!(
        alerts.iter().any(|a| a.summary_key == "udp_flood"),
        "{alerts:#?}"
    );
}

#[test]
fn slightly_reordered_packets_are_still_counted() {
    // Reverse every 100-packet chunk: timestamps go backwards by up to 1 ms constantly.
    let packets = syn_flood(ATTACKER_SYN, T0, 15, 100);
    let shuffled: Vec<_> = packets
        .chunks(100)
        .flat_map(|c| c.iter().rev().copied())
        .collect();
    let mut engine = Engine::new(Config::default());
    let alerts = replay(&mut engine, shuffled, &[], T0, T0 + secs(40));
    assert!(
        has_started(&alerts, "syn_flood", Some(ATTACKER_SYN)),
        "{alerts:#?}"
    );
    assert!(engine.stats().time_regressions > 0);
}

#[test]
fn late_failed_logons_outside_the_window_are_ignored() {
    let mut engine = Engine::new(Config::default());
    let _ = engine.tick(T0 + secs(10_000));
    for f in rdp_failures(ATTACKER_RDP, T0, 50, SECOND) {
        engine.observe_logon_failure(f.ip, f.at_ns);
    }
    assert!(engine.tick(T0 + secs(10_001)).is_empty());
    assert_eq!(engine.tracked_logon_sources(), 0);
}
