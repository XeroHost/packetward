// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Bounded memory under hostile input, and a throughput smoke test. Streams are generated lazily and
//! the engine is ticked every simulated second, so eviction really runs.

use std::time::{Duration, Instant};

use crate::testgen::*;
use crate::{Config, ConnectionCounts, Engine};

use super::{has_started, secs};

fn assert_bounded(e: &Engine, config: &Config) {
    let l = &config.limits;
    assert!(
        e.tracked_sources() <= l.max_sources,
        "sources {}",
        e.tracked_sources()
    );
    assert!(e.scan_trackers_in_use() <= l.max_scan_trackers);
    assert!(e.open_incidents() <= l.max_incidents);
    assert!(e.tracked_connection_sources() <= l.max_conn_sources);
    assert!(e.tracked_logon_sources() <= l.max_logon_sources);
}

#[test]
fn two_million_spoofed_sources_do_not_grow_the_table_past_its_cap() {
    let config = Config::default();
    let mut engine = Engine::new(config.clone());
    let mut peak = 0usize;
    // 2 000 000 SYNs from 2 000 000 distinct addresses over 20 simulated seconds.
    let flood = spoofed_syn_iter(1, T0, 100_000, 2_000_000);
    let alerts = replay_with(&mut engine, flood, &[], T0, T0 + secs(25), |e, _| {
        assert_bounded(e, &config);
        peak = peak.max(e.tracked_sources());
    });
    assert!(peak <= config.limits.max_sources);
    assert!(
        peak >= config.limits.max_sources * 3 / 4,
        "the flood did fill the table: {peak}"
    );
    let stats = engine.stats();
    assert_eq!(stats.packets_inbound, 2_000_000);
    assert!(stats.packets_untracked > 0);
    assert!(stats.sources_evicted > 0);
    // Spoofed SYNs are still visible in aggregate.
    assert!(
        has_started(&alerts, "syn_flood_distributed", None),
        "{alerts:#?}"
    );

    // The flood ends: every entry expires and the table empties by itself.
    for s in 26..120u64 {
        let _ = engine.tick(T0 + secs(s));
    }
    assert_eq!(engine.tracked_sources(), 0);
}

#[test]
fn a_real_attacker_is_still_found_inside_a_spoofed_flood() {
    let config = Config::default();
    let mut engine = Engine::new(config.clone());
    let spoof = spoofed_udp_iter(2, T0, 60_000, 1_800_000);
    let attack = syn_flood(ATTACKER_SYN, T0 + secs(3), 25, 2_000).into_iter();
    let alerts = replay_with(
        &mut engine,
        interleave(spoof, attack),
        &[],
        T0,
        T0 + secs(40),
        |e, _| {
            assert_bounded(e, &config);
        },
    );
    assert!(
        has_started(&alerts, "syn_flood", Some(ATTACKER_SYN)),
        "{alerts:#?}"
    );
}

#[test]
fn two_million_legitimate_packets_stay_quiet_bounded_and_fast_enough() {
    let config = Config::default();
    let mut engine = Engine::new(config.clone());
    let began = Instant::now();
    let alerts = replay_with(
        &mut engine,
        legit_iter(9, T0, 200_000, 2_000_000),
        &[],
        T0,
        T0 + secs(30),
        |e, _| {
            assert_bounded(e, &config);
        },
    );
    let took = began.elapsed();
    assert!(alerts.is_empty(), "{alerts:#?}");
    assert_eq!(engine.stats().packets_inbound, 2_000_000);
    // Generous: even an unoptimised debug build on a slow CI machine manages this in seconds.
    assert!(took < Duration::from_secs(240), "took {took:?}");
}

#[test]
fn many_scanners_cannot_exhaust_memory_through_scan_trackers() {
    let mut config = Config::default();
    config.limits.max_scan_trackers = 64;
    let mut engine = Engine::new(config.clone());
    // 3000 sources each probing 12 distinct ports: each wants a tracker.
    let packets: Vec<_> = (0..3_000u32)
        .flat_map(|s| {
            (0..12u16).map(move |p| {
                inbound_tcp(
                    T0 + u64::from(s) * 1_000_000 + u64::from(p),
                    client_ip(s),
                    40_000,
                    1_000 + p,
                    pw_core::TCP_SYN,
                    44,
                )
            })
        })
        .collect();
    replay_with(&mut engine, packets, &[], T0, T0 + secs(10), |e, _| {
        assert_bounded(e, &config)
    });
    assert!(engine.stats().scan_tracker_exhausted > 0);
    // After everything expires, trackers are recycled.
    for s in 11..200u64 {
        let _ = engine.tick(T0 + secs(s));
    }
    assert_eq!(engine.scan_trackers_in_use(), 0);
    assert_eq!(engine.tracked_sources(), 0);
}

#[test]
fn connection_and_logon_tables_are_bounded() {
    let config = Config::default();
    let mut engine = Engine::new(config.clone());
    engine.observe_connection_counts(
        T0,
        (0..100_000u32).map(|i| {
            (
                client_ip(i),
                ConnectionCounts {
                    concurrent: 10,
                    new: 0,
                },
            )
        }),
    );
    assert_eq!(
        engine.tracked_connection_sources(),
        config.limits.max_conn_sources
    );
    for i in 0..100_000u32 {
        engine.observe_logon_failure(client_ip(i), T0 + u64::from(i) * 1_000);
    }
    assert_eq!(
        engine.tracked_logon_sources(),
        config.limits.max_logon_sources
    );
    assert_bounded(&engine, &config);
    // A flooded address still triggers while the table churns.
    for _ in 0..12 {
        engine.observe_logon_failure(ATTACKER_RDP, T0 + secs(1));
    }
    assert!(engine
        .tick(T0 + secs(2))
        .iter()
        .any(|a| a.summary_key == "rdp_brute_force"));
    // Everything ages out.
    let _ = engine.tick(T0 + secs(1_000));
    assert_eq!(engine.tracked_logon_sources(), 0);
    assert_eq!(engine.tracked_connection_sources(), 0);
}

#[test]
fn per_source_memory_matches_the_documented_budget() {
    let size = std::mem::size_of::<crate::engine::Source>();
    // `Limits::max_sources` documents ~0.7 KB per source; keep the struct honest.
    assert!(size <= 760, "Source grew to {size} bytes");
}
