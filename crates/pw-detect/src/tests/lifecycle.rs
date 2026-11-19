// SPDX-License-Identifier: GPL-3.0-or-later
//! One attack, one alert: dedup, escalation, ending, cooldown, protection flag and caps on alerts.

use pw_core::CidrSet;

use crate::testgen::*;
use crate::{Alert, AlertPhase, Config, Engine, Severity};

use super::{run, secs};

const END: u64 = T0 + 600 * SECOND;

fn phases(alerts: &[Alert]) -> Vec<(AlertPhase, Severity)> {
    alerts.iter().map(|a| (a.phase, a.severity)).collect()
}

#[test]
fn a_two_minute_attack_is_one_started_and_one_ended() {
    let alerts = run(
        Config::default(),
        syn_flood(ATTACKER_SYN, T0, 120, 100),
        &[],
        T0,
        END,
    );
    assert_eq!(
        phases(&alerts),
        vec![
            (AlertPhase::Started, Severity::High),
            (AlertPhase::Ended, Severity::High)
        ]
    );
    assert_eq!(alerts[0].id, alerts[1].id);
}

#[test]
fn rising_intensity_escalates_the_same_incident_once() {
    // 100 pps (1000 SYN / 10 s: High), then 1000 pps (10 000 / 10 s: 2000 x5... level 1 -> Critical).
    let packets = merge(vec![
        syn_flood(ATTACKER_SYN, T0, 10, 100),
        syn_flood(ATTACKER_SYN, T0 + secs(10), 15, 1_000),
    ]);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        phases(&alerts),
        vec![
            (AlertPhase::Started, Severity::High),
            (AlertPhase::Escalated, Severity::Critical),
            (AlertPhase::Ended, Severity::Critical),
        ],
        "{alerts:#?}"
    );
    assert!(alerts.iter().all(|a| a.id == alerts[0].id));
    // The Ended alert carries the peak metrics.
    assert!(alerts[2].metric("syn").is_some_and(|v| v >= 9_000));
}

#[test]
fn a_pause_shorter_than_the_cooldown_does_not_end_or_restart() {
    let packets = merge(vec![
        syn_flood(ATTACKER_SYN, T0, 10, 100),
        syn_flood(ATTACKER_SYN, T0 + secs(40), 10, 100),
    ]);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        phases(&alerts),
        vec![
            (AlertPhase::Started, Severity::High),
            (AlertPhase::Ended, Severity::High)
        ],
        "{alerts:#?}"
    );
}

#[test]
fn an_attack_that_resumes_after_it_ended_is_a_new_incident() {
    let packets = merge(vec![
        syn_flood(ATTACKER_SYN, T0, 10, 100),
        syn_flood(ATTACKER_SYN, T0 + secs(300), 10, 100),
    ]);
    let alerts = run(Config::default(), packets, &[], T0, END);
    assert_eq!(
        alerts.iter().map(|a| a.phase).collect::<Vec<_>>(),
        vec![
            AlertPhase::Started,
            AlertPhase::Ended,
            AlertPhase::Started,
            AlertPhase::Ended
        ]
    );
    assert_ne!(alerts[0].id, alerts[2].id);
    assert!(alerts[2].id > alerts[0].id);
}

#[test]
fn different_detectors_and_sources_are_independent_incidents() {
    let packets = merge(vec![
        syn_flood(ATTACKER_SYN, T0, 15, 100),
        syn_flood(ATTACKER_UDP, T0, 15, 100),
        udp_flood(ATTACKER_SYN, T0, 15, 20_000, 1000),
    ]);
    let alerts = run(Config::default(), packets, &[], T0, END);
    let mut keys: Vec<_> = super::started(&alerts);
    keys.sort();
    assert_eq!(
        keys,
        vec![
            ("syn_flood", Some(ATTACKER_SYN)),
            ("syn_flood", Some(ATTACKER_UDP)),
            ("udp_flood", Some(ATTACKER_SYN)),
        ]
    );
    let mut ids: Vec<_> = alerts
        .iter()
        .filter(|a| a.phase == AlertPhase::Started)
        .map(|a| a.id)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3);
}

#[test]
fn alerts_are_always_raised_and_flagged_when_the_source_is_protected() {
    let mut engine = Engine::new(Config::default());
    let mut protected = CidrSet::new();
    assert!(protected.insert_str("203.0.113.1").is_ok());
    engine.set_protected(protected);
    let packets = merge(vec![
        syn_flood(ATTACKER_SYN, T0, 15, 100),
        syn_flood(ATTACKER_UDP, T0, 15, 100),
    ]);
    let alerts = replay(&mut engine, packets, &[], T0, END);
    let flag = |ip| {
        alerts
            .iter()
            .filter(|a| a.source == Some(ip))
            .map(|a| a.protected)
            .collect::<Vec<_>>()
    };
    assert_eq!(flag(ATTACKER_SYN), vec![true, true], "raised, and flagged");
    assert_eq!(flag(ATTACKER_UDP), vec![false, false]);

    // Unattributed alerts are never protected, even by a catch-all set.
    let mut everything = CidrSet::new();
    assert!(everything.insert_str("0.0.0.0/0").is_ok());
    let mut engine = Engine::new(Config::default());
    engine.set_protected(everything);
    let alerts = replay(
        &mut engine,
        spoofed_syn_flood(1, T0, 15, 5_000),
        &[],
        T0,
        END,
    );
    assert!(
        alerts.iter().all(|a| a.source.is_none() && !a.protected),
        "{alerts:#?}"
    );
    assert!(!alerts.is_empty());
}

#[test]
fn new_alerts_per_tick_are_capped_and_the_rest_follow_on_later_ticks() {
    let mut config = Config::default();
    config.limits.max_new_alerts_per_tick = 5;
    let packets = merge(
        (0..30)
            .map(|i| syn_flood(client_ip(i), T0, 20, 100))
            .collect(),
    );
    let mut engine = Engine::new(config);
    let mut per_tick = Vec::new();
    let alerts = replay_with(&mut engine, packets, &[], T0, T0 + secs(30), |_, tick| {
        per_tick.push(
            tick.iter()
                .filter(|a| a.phase == AlertPhase::Started)
                .count(),
        );
    });
    assert!(per_tick.iter().all(|n| *n <= 5), "{per_tick:?}");
    assert_eq!(
        alerts
            .iter()
            .filter(|a| a.phase == AlertPhase::Started)
            .count(),
        30
    );
    assert!(engine.stats().alerts_deferred > 0);
    // Ordering of who goes first is deterministic: ids follow (severity, kind, key, source).
    let first_tick: Vec<_> = alerts
        .iter()
        .filter(|a| a.phase == AlertPhase::Started)
        .take(5)
        .filter_map(|a| a.source)
        .collect();
    let mut sorted = first_tick.clone();
    sorted.sort();
    assert_eq!(first_tick, sorted);
}

#[test]
fn open_incidents_are_capped() {
    let mut config = Config::default();
    config.limits.max_incidents = 16;
    let packets = merge(
        (0..40)
            .map(|i| syn_flood(client_ip(i), T0, 20, 100))
            .collect(),
    );
    let mut engine = Engine::new(config);
    let mut peak = 0;
    let alerts = replay_with(&mut engine, packets, &[], T0, T0 + secs(25), |e, _| {
        peak = peak.max(e.open_incidents());
    });
    assert_eq!(peak, 16);
    assert_eq!(
        alerts
            .iter()
            .filter(|a| a.phase == AlertPhase::Started)
            .count(),
        16
    );
    assert!(engine.stats().incidents_refused > 0);
}

#[test]
fn disabled_detectors_stay_silent() {
    let mut config = Config::default();
    config.syn_flood.enabled = false;
    config.syn_flood.global_min_syn = 0;
    let alerts = run(config, syn_flood(ATTACKER_SYN, T0, 15, 100), &[], T0, END);
    assert!(alerts.is_empty(), "{alerts:#?}");
}

#[test]
fn changing_the_config_keeps_open_incidents() {
    let mut engine = Engine::new(Config::default());
    let packets = syn_flood(ATTACKER_SYN, T0, 30, 100);
    let alerts = replay(
        &mut engine,
        packets[..1_500].iter().copied(),
        &[],
        T0,
        T0 + secs(15),
    );
    assert_eq!(alerts.len(), 1);
    engine.set_config(Config::preset(crate::Preset::Strict));
    assert_eq!(engine.open_incidents(), 1);
    assert_eq!(engine.config().syn_flood.min_syn, 100);
}
