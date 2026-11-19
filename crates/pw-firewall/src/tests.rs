// SPDX-License-Identifier: GPL-3.0-or-later
//! Behaviour tests of the guarded manager against the in-memory fake.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use pw_core::{Cidr, CidrSet};

use crate::fake::{FakeFirewall, FakeOp};
use crate::guard::CONFIRMATION_PHRASE;
use crate::*;

fn cidr(t: &str) -> Cidr {
    t.parse().unwrap()
}

fn ip(t: &str) -> IpAddr {
    t.parse().unwrap()
}

fn host(n: u32) -> Cidr {
    Cidr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n)), 32).unwrap()
}

fn hosts(range: std::ops::Range<u32>) -> Vec<Cidr> {
    range.map(host).collect()
}

fn protected(blocks: &[&str]) -> CidrSet {
    let mut s = CidrSet::new();
    for b in blocks {
        s.insert_str(b).unwrap();
    }
    s
}

fn manager() -> FirewallManager<FakeFirewall> {
    FirewallManager::new(FakeFirewall::windows_defaults())
}

fn pw_rules(m: &FirewallManager<FakeFirewall>) -> Vec<Rule> {
    m.backend()
        .rules()
        .into_iter()
        .filter(Rule::is_managed)
        .collect()
}

fn confirmation() -> Confirmation {
    Confirmation::from_phrase(CONFIRMATION_PHRASE).unwrap()
}

// ---- batching ------------------------------------------------------------------------------

#[test]
fn five_thousand_blocked_ips_use_fewer_than_ten_rules() {
    let m = manager();
    let none = CidrSet::new();
    let out = m
        .apply_blocklist(&BatchId::auto_block(), &hosts(0..5000), &BlockOptions::new(&none))
        .unwrap();
    assert_eq!(out.total_blocked, 5000);
    assert_eq!(out.rules, 5);
    let rules = pw_rules(&m);
    assert_eq!(rules.len(), 5);
    assert!(rules.len() < 10);
    for r in &rules {
        assert_eq!(r.grouping, GROUP);
        assert!(r.has_marker());
        assert_eq!(r.action, Action::Block);
        assert_eq!(r.direction, Direction::Inbound);
        assert!(r.enabled);
        assert!(r.remote_cidrs().0.len() <= 1000);
        assert_eq!(r.remote_cidrs().1, 0);
    }
    let names: Vec<_> = rules.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names[0], "PW-AutoBlock-001");
    assert_eq!(m.list_blocks(&BatchId::auto_block()).unwrap().len(), 5000);
}

#[test]
fn updates_rewrite_only_the_changed_batches() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    let batch = BatchId::auto_block();
    m.apply_blocklist(&batch, &hosts(0..5000), &opts).unwrap();
    m.backend().clear_log();

    // Same list again (Windows reads addresses back in mask form): no write at all.
    let out = m.apply_blocklist(&batch, &hosts(0..5000), &opts).unwrap();
    assert_eq!(out.rule_writes, 0);
    assert!(m.backend().writes().is_empty());

    // Unblock one address: exactly one rule is rewritten.
    let out = m.unblock_ips(&batch, &[host(4242)]).unwrap();
    assert_eq!(out.removed, vec![host(4242)]);
    assert_eq!(
        m.backend().writes(),
        vec![FakeOp::Update("PW-AutoBlock-005".into())]
    );

    // Block one new address: it takes the room that was freed, in the same single rule.
    m.backend().clear_log();
    m.block_ips(&batch, &[host(9000)], &opts).unwrap();
    assert_eq!(
        m.backend().writes(),
        vec![FakeOp::Update("PW-AutoBlock-005".into())]
    );
    assert_eq!(pw_rules(&m).len(), 5);
}

#[test]
fn manual_and_list_batches_are_independent_of_auto_blocks() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    m.block_ips(&BatchId::manual(), &[cidr("198.51.100.0/24")], &opts).unwrap();
    m.apply_blocklist(&BatchId::list("XeroHost shared").unwrap(), &hosts(0..10), &opts).unwrap();
    m.apply_blocklist(&BatchId::auto_block(), &hosts(100..110), &opts).unwrap();
    // The Guardian expires everything it had: the others stay.
    m.apply_blocklist(&BatchId::auto_block(), &[], &opts).unwrap();
    assert_eq!(m.list_blocks(&BatchId::manual()).unwrap(), vec![cidr("198.51.100.0/24")]);
    assert_eq!(m.list_blocks(&BatchId::list("xerohost shared").unwrap()).unwrap().len(), 10);
    assert!(m.list_blocks(&BatchId::auto_block()).unwrap().is_empty());
    let names: Vec<String> = pw_rules(&m).into_iter().map(|r| r.name).collect();
    assert!(names.contains(&"PW-Manual-001".to_owned()));
    assert!(names.contains(&"PW-List-xerohost-shared-001".to_owned()));
    assert!(!names.iter().any(|n| n.starts_with("PW-AutoBlock")));
}

#[test]
fn expiry_is_applied_by_reconcile_blocks() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    let batch = BatchId::auto_block();
    let d = |n, e| DesiredBlock {
        block: host(n),
        expires_at: e,
    };
    let out = m
        .reconcile_blocks(&batch, &[d(1, Some(100)), d(2, Some(200)), d(3, None)], 50, &opts)
        .unwrap();
    assert_eq!(out.total_blocked, 3);
    let out = m
        .reconcile_blocks(&batch, &[d(1, Some(100)), d(2, Some(200)), d(3, None)], 150, &opts)
        .unwrap();
    assert_eq!(out.expired, vec![host(1)]);
    assert_eq!(out.removed, vec![host(1)]);
    assert_eq!(m.list_blocks(&batch).unwrap(), vec![host(2), host(3)]);
}

#[test]
fn a_rule_never_ends_up_with_no_addresses_and_gone_is_gone() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    let batch = BatchId::auto_block();
    m.block_ips(&batch, &hosts(0..3), &opts).unwrap();
    m.unblock_ips(&batch, &hosts(0..3)).unwrap();
    assert!(pw_rules(&m).is_empty());
    // Everything is idempotent.
    let out = m.unblock_ips(&batch, &hosts(0..3)).unwrap();
    assert_eq!(out.not_present.len(), 3);
    assert_eq!(out.rule_writes, 0);
    assert_eq!(m.clear_batch(&batch).unwrap(), 0);
    assert!(m.apply_blocklist(&batch, &[], &opts).unwrap().rule_writes == 0);
}

#[test]
fn a_crash_half_way_converges_on_retry() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    let batch = BatchId::auto_block();
    m.backend().fail_writes_after(2);
    assert!(m.apply_blocklist(&batch, &hosts(0..5000), &opts).is_err());
    assert_eq!(pw_rules(&m).len(), 2);
    m.backend().heal();
    m.apply_blocklist(&batch, &hosts(0..5000), &opts).unwrap();
    assert_eq!(pw_rules(&m).len(), 5);
    assert_eq!(m.list_blocks(&batch).unwrap().len(), 5000);
}

#[test]
fn a_wrong_rule_in_the_batch_is_repaired_not_trusted() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    let batch = BatchId::auto_block();
    m.block_ips(&batch, &hosts(0..3), &opts).unwrap();
    // Somebody disabled it and turned it into an allow rule.
    m.backend().tamper("PW-AutoBlock-001", |r| {
        r.enabled = false;
        r.action = Action::Allow;
    });
    m.backend().clear_log();
    m.apply_blocklist(&batch, &hosts(0..3), &opts).unwrap();
    assert_eq!(m.backend().writes(), vec![FakeOp::Update("PW-AutoBlock-001".into())]);
    let r = m.backend().rule("PW-AutoBlock-001").unwrap();
    assert!(r.enabled && r.action == Action::Block);

    // A hand-edited wildcard ("block everyone") is rewritten, or deleted when nothing is wanted.
    m.backend().tamper("PW-AutoBlock-001", |r| r.remote_addresses = "*".into());
    m.apply_blocklist(&batch, &hosts(0..3), &opts).unwrap();
    assert_eq!(m.list_blocks(&batch).unwrap(), hosts(0..3));
    m.backend().tamper("PW-AutoBlock-001", |r| r.remote_addresses = "*".into());
    m.apply_blocklist(&batch, &[], &opts).unwrap();
    assert!(pw_rules(&m).is_empty());
}

// ---- protected set -------------------------------------------------------------------------

#[test]
fn a_batch_with_a_protected_address_is_refused_with_nothing_applied() {
    let m = manager();
    let guard_set = protected(&["203.0.113.9", "192.0.2.0/24"]);
    let opts = BlockOptions::new(&guard_set);
    let batch = BatchId::auto_block();
    let err = m
        .block_ips(&batch, &[host(1), cidr("203.0.113.9"), cidr("192.0.2.5"), host(2)], &opts)
        .unwrap_err();
    match err {
        FirewallError::Refused(r) => {
            assert_eq!(r.protected, vec![cidr("203.0.113.9"), cidr("192.0.2.5")]);
        }
        other => panic!("{other:?}"),
    }
    assert!(m.backend().writes().is_empty());
    assert!(pw_rules(&m).is_empty());
    // Same for a whole blocklist.
    assert!(m.apply_blocklist(&batch, &[host(1), cidr("203.0.113.0/24")], &opts).is_err());
    assert!(m.backend().writes().is_empty());
}

#[test]
fn skip_protected_applies_the_rest_and_reports() {
    let m = manager();
    let guard_set = protected(&["203.0.113.9"]);
    let opts = BlockOptions::new(&guard_set).skip_protected();
    let out = m
        .block_ips(&BatchId::auto_block(), &[host(1), cidr("203.0.113.9"), host(2)], &opts)
        .unwrap();
    assert_eq!(out.skipped_protected, vec![cidr("203.0.113.9")]);
    assert_eq!(out.added, vec![host(1), host(2)]);
}

#[test]
fn loopback_gateway_style_floor_cannot_be_blocked_even_with_no_protected_set() {
    let m = manager();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none).allow_broad();
    for bad in ["127.0.0.1", "0.0.0.0/0", "::/0", "::1", "169.254.0.0/16", "fe80::/10"] {
        assert!(
            m.block_ips(&BatchId::auto_block(), &[cidr(bad)], &opts).is_err(),
            "{bad}"
        );
    }
    assert!(m.backend().writes().is_empty());
}

#[test]
fn absurdly_broad_prefixes_need_the_override() {
    let m = manager();
    let none = CidrSet::new();
    let batch = BatchId::manual();
    assert!(matches!(
        m.block_ips(&batch, &[cidr("8.0.0.0/6")], &BlockOptions::new(&none)),
        Err(FirewallError::Refused(r)) if r.too_broad == vec![cidr("8.0.0.0/6")]
    ));
    assert!(m.block_ips(&batch, &[cidr("10.0.0.0/8")], &BlockOptions::new(&none)).is_ok());
    assert!(m
        .block_ips(&batch, &[cidr("8.0.0.0/6")], &BlockOptions::new(&none).allow_broad())
        .is_ok());
}

#[test]
fn existing_blocks_that_became_protected_are_evicted() {
    let m = manager();
    let none = CidrSet::new();
    let batch = BatchId::auto_block();
    m.block_ips(&batch, &[host(1), host(2)], &BlockOptions::new(&none)).unwrap();
    // host(2) turns out to be the RDP client now.
    let guard_set = protected(&["10.0.0.2"]);
    let out = m
        .block_ips(&batch, &[host(3)], &BlockOptions::new(&guard_set))
        .unwrap();
    assert_eq!(out.evicted_protected, vec![host(2)]);
    assert_eq!(m.list_blocks(&batch).unwrap(), vec![host(1), host(3)]);
}

// ---- foreign rules -------------------------------------------------------------------------

fn user_rule(name: &str) -> Rule {
    let mut r = Rule::new(name, Direction::Inbound, Action::Allow);
    r.protocol = Protocol::Tcp;
    r.local_ports = "8080".into();
    r.description = "my web".into();
    r
}

#[test]
fn foreign_rules_are_read_only_unless_the_flag_is_given() {
    let m = manager();
    let name = "File and Printer Sharing (SMB-In)";
    let opts = RuleOptions::default();
    assert_eq!(m.set_enabled(name, true, &opts), Err(FirewallError::ForeignRule(name.into())));
    assert_eq!(m.remove_rule(name, &opts), Err(FirewallError::ForeignRule(name.into())));
    let mut changed = m.get_rule(name).unwrap().unwrap();
    changed.local_ports = "446".into();
    assert!(matches!(m.update_rule(name, &changed, &opts), Err(FirewallError::ForeignRule(_))));
    assert!(!m.backend().rule(name).unwrap().enabled);

    m.set_enabled(name, true, &opts.foreign_edit()).unwrap();
    assert!(m.backend().rule(name).unwrap().enabled);
    m.update_rule(name, &changed, &opts.foreign_edit()).unwrap();
    let after = m.backend().rule(name).unwrap();
    assert_eq!(after.local_ports, "446");
    // Editing a foreign rule never moves it into our group.
    assert_eq!(after.grouping, "File and Printer Sharing");
    m.remove_rule(name, &opts.foreign_edit()).unwrap();
    assert!(m.backend().rule(name).is_none());
}

#[test]
fn user_rules_get_the_group_and_marker_and_can_be_edited_freely() {
    let m = manager();
    let opts = RuleOptions::default();
    m.add_rule(&user_rule("My web"), &opts).unwrap();
    let r = m.backend().rule("My web").unwrap();
    assert_eq!(r.grouping, GROUP);
    assert!(r.description.contains(MARKER) && r.description.contains("my web"));
    assert_eq!(m.add_rule(&user_rule("my WEB"), &opts), Err(FirewallError::AlreadyExists("my WEB".into())));
    let mut edited = user_rule("My web");
    edited.local_ports = "9090".into();
    edited.grouping = "Hacker".into(); // ignored
    m.update_rule("My web", &edited, &opts).unwrap();
    let r = m.backend().rule("My web").unwrap();
    assert_eq!((r.local_ports.as_str(), r.grouping.as_str()), ("9090", GROUP));
    m.set_enabled("My web", false, &opts).unwrap();
    m.remove_rule("My web", &opts).unwrap();
    assert!(m.backend().rule("My web").is_none());
    assert_eq!(m.remove_rule("My web", &opts), Err(FirewallError::NotFound("My web".into())));
}

#[test]
fn reserved_and_hostile_names_and_bad_fields_are_rejected() {
    let m = manager();
    let opts = RuleOptions::default();
    for bad in ["PW-AutoBlock-001", "pw-x", "a|b", "x\"y", "", "@FirewallAPI.dll,-1"] {
        assert!(
            matches!(m.add_rule(&user_rule(bad), &opts), Err(FirewallError::InvalidName { .. })),
            "{bad:?}"
        );
    }
    let mut r = user_rule("ok");
    r.local_ports = "80;rm".into();
    assert!(matches!(m.add_rule(&r, &opts), Err(FirewallError::InvalidRule(_))));
    let mut r = user_rule("ok");
    r.protocol = Protocol::Any; // ports need TCP/UDP
    assert!(matches!(m.add_rule(&r, &opts), Err(FirewallError::InvalidRule(_))));
    let mut r = user_rule("ok");
    r.remote_addresses = "1.2.3.4,not-an-ip".into();
    assert!(matches!(m.add_rule(&r, &opts), Err(FirewallError::InvalidRule(_))));
    assert!(m.backend().writes().is_empty());
}

#[test]
fn batch_rules_cannot_be_hand_edited_through_the_generic_api() {
    let m = manager();
    let none = CidrSet::new();
    m.block_ips(&BatchId::auto_block(), &[host(1)], &BlockOptions::new(&none)).unwrap();
    let r = m.get_rule("PW-AutoBlock-001").unwrap().unwrap();
    assert!(matches!(
        m.update_rule("PW-AutoBlock-001", &r, &RuleOptions::default()),
        Err(FirewallError::BatchManaged(_))
    ));
}

#[test]
fn generic_block_rules_need_the_protected_set_and_are_screened() {
    let m = manager();
    let mut r = Rule::new("Block bad", Direction::Inbound, Action::Block);
    r.remote_addresses = "198.51.100.0/24".into();
    assert_eq!(
        m.add_rule(&r, &RuleOptions::default()),
        Err(FirewallError::ProtectedSetRequired)
    );
    let guard_set = protected(&["198.51.100.7"]);
    assert!(matches!(
        m.add_rule(&r, &RuleOptions::default().protecting(&guard_set)),
        Err(FirewallError::Refused(_))
    ));
    let other = protected(&["203.0.113.1"]);
    m.add_rule(&r, &RuleOptions::default().protecting(&other)).unwrap();
}

// ---- purge ---------------------------------------------------------------------------------

#[test]
fn purge_removes_the_packetward_group_and_nothing_else() {
    let m = manager();
    let before_foreign: Vec<Rule> = m.backend().rules();
    let none = CidrSet::new();
    let opts = BlockOptions::new(&none);
    m.apply_blocklist(&BatchId::auto_block(), &hosts(0..2500), &opts).unwrap();
    m.block_ips(&BatchId::manual(), &[host(9000)], &opts).unwrap();
    m.add_rule(&user_rule("My web"), &RuleOptions::default()).unwrap();
    // A foreign rule that merely *looks* like ours (name prefix, other group) must survive.
    let mut lookalike = Rule::new("PW-Impostor-001", Direction::Inbound, Action::Allow);
    lookalike.grouping = "Somebody Else".into();
    lookalike.description = MARKER.into();
    m.backend().seed(lookalike);

    let report = m.purge(&RuleOptions::default()).unwrap();
    assert_eq!(report.removed.len(), 3 + 1 + 1);
    assert!(pw_rules(&m).is_empty());
    let after = m.backend().rules();
    assert_eq!(after.len(), before_foreign.len() + 1);
    assert!(after.iter().any(|r| r.name == "PW-Impostor-001"));
    for r in &before_foreign {
        assert!(after.contains(r), "{} was touched", r.name);
    }
    // Idempotent.
    m.backend().clear_log();
    assert!(m.purge(&RuleOptions::default()).unwrap().removed.is_empty());
    assert!(m.backend().writes().is_empty());
}

#[test]
fn purge_with_an_active_rdp_restriction_needs_the_confirmation() {
    let m = manager();
    let c = confirmation();
    let allowed = [cidr("203.0.113.0/24")];
    m.rdp_restrict(
        &RdpRestrict {
            port: 3389,
            allowed: &allowed,
            required_clients: &[ip("203.0.113.5")],
            include_udp: true,
            disable_builtin: true,
        },
        1,
        &RuleOptions::default().confirmed(&c),
    )
    .unwrap();
    assert!(matches!(
        m.purge(&RuleOptions::default()),
        Err(FirewallError::ConfirmationRequired { .. })
    ));
    assert!(!pw_rules(&m).is_empty());
    m.purge(&RuleOptions::default().confirmed(&c)).unwrap();
    assert!(pw_rules(&m).is_empty());
}

// ---- lockout guards ------------------------------------------------------------------------

#[test]
fn builtin_rdp_rules_need_the_typed_confirmation_to_delete_or_disable() {
    let m = manager();
    let name = "Remote Desktop - User Mode (TCP-In)";
    let plain = RuleOptions::default().foreign_edit();
    assert!(matches!(
        m.remove_rule(name, &plain),
        Err(FirewallError::ConfirmationRequired { reason: LockoutReason::BuiltinRdpRule, .. })
    ));
    assert!(matches!(
        m.set_enabled(name, false, &plain),
        Err(FirewallError::ConfirmationRequired { .. })
    ));
    let mut edit = m.get_rule(name).unwrap().unwrap();
    edit.remote_addresses = "203.0.113.0/24".into();
    assert!(matches!(
        m.update_rule(name, &edit, &plain),
        Err(FirewallError::ConfirmationRequired { .. })
    ));
    assert!(m.backend().writes().is_empty());
    // A wrong phrase is not a confirmation at all.
    assert!(Confirmation::from_phrase("yes please").is_err());
    let c = confirmation();
    m.set_enabled(name, false, &plain.confirmed(&c)).unwrap();
    assert!(!m.backend().rule(name).unwrap().enabled);
    // Re-enabling never needs it.
    m.set_enabled(name, true, &plain).unwrap();
    m.remove_rule(name, &plain.confirmed(&c)).unwrap();
}

#[test]
fn an_inbound_allow_rule_for_the_rdp_port_is_guarded_like_the_builtin_ones() {
    let m = manager();
    let mut mine = Rule::new("Corp RDP", Direction::Inbound, Action::Allow);
    mine.protocol = Protocol::Tcp;
    mine.local_ports = "3390".into();
    m.add_rule(&mine, &RuleOptions::default()).unwrap();
    // Port 3390 is not the RDP port yet: free to remove.
    m.set_enabled("Corp RDP", false, &RuleOptions::default()).unwrap();
    m.set_enabled("Corp RDP", true, &RuleOptions::default()).unwrap();
    m.set_rdp_port(3390);
    assert!(matches!(
        m.remove_rule("Corp RDP", &RuleOptions::default()),
        Err(FirewallError::ConfirmationRequired { reason: LockoutReason::RdpPortAllow { port: 3390 }, .. })
    ));
}

#[test]
fn a_block_rule_that_cuts_rdp_off_for_everyone_needs_the_confirmation() {
    let m = manager();
    let guard_set = protected(&["203.0.113.1"]);
    let opts = RuleOptions::default().protecting(&guard_set);
    let mut r = Rule::new("Block RDP", Direction::Inbound, Action::Block);
    r.protocol = Protocol::Tcp;
    r.local_ports = "3389".into();
    assert!(matches!(
        m.add_rule(&r, &opts),
        Err(FirewallError::ConfirmationRequired { reason: LockoutReason::BlocksRdp { .. }, .. })
    ));
    // Blocking RDP from one network is an ordinary rule.
    r.remote_addresses = "198.51.100.0/24".into();
    m.add_rule(&r, &opts).unwrap();
    // A different port for everyone is fine too.
    let mut smb = Rule::new("Block SMB", Direction::Inbound, Action::Block);
    smb.protocol = Protocol::Tcp;
    smb.local_ports = "445".into();
    m.add_rule(&smb, &opts).unwrap();
    // Re-enabling a disabled rule that cuts RDP off is guarded as well.
    let mut disabled = Rule::new("Block RDP all", Direction::Inbound, Action::Block);
    disabled.protocol = Protocol::Tcp;
    disabled.local_ports = "3389".into();
    disabled.enabled = false;
    m.add_rule(&disabled, &opts).unwrap();
    assert!(matches!(
        m.set_enabled("Block RDP all", true, &RuleOptions::default()),
        Err(FirewallError::ConfirmationRequired { .. })
    ));
}

// ---- RDP shield ------------------------------------------------------------------------------

fn sorted(mut rules: Vec<Rule>) -> Vec<Rule> {
    rules.sort_by(|a, b| a.name.cmp(&b.name));
    rules
}

#[test]
fn restrict_and_restore_round_trip_through_a_serialized_snapshot() {
    let m = manager();
    let original = sorted(m.backend().rules());
    let allowed = [cidr("203.0.113.0/24"), cidr("2001:db8::/32")];
    let req = RdpRestrict {
        port: 3389,
        allowed: &allowed,
        required_clients: &[ip("203.0.113.77"), ip("2001:db8::5")],
        include_udp: true,
        disable_builtin: true,
    };
    // Disabling the built-in rules needs the typed confirmation; nothing changes without it.
    assert!(matches!(
        m.rdp_restrict(&req, 1_000, &RuleOptions::default()),
        Err(FirewallError::ConfirmationRequired { reason: LockoutReason::RestrictRdp, .. })
    ));
    assert!(m.backend().writes().is_empty());

    let c = confirmation();
    let out = m.rdp_restrict(&req, 1_000, &RuleOptions::default().confirmed(&c)).unwrap();
    assert_eq!(out.created_or_updated, vec![RDP_ALLOW_TCP_NAME, RDP_ALLOW_UDP_NAME]);
    assert_eq!(out.disabled.len(), 2);
    // The allow rule exists before any built-in rule was switched off.
    let log = m.backend().writes();
    let first_disable = log.iter().position(|op| matches!(op, FakeOp::SetEnabled(..))).unwrap();
    let last_add = log.iter().rposition(|op| matches!(op, FakeOp::Add(_))).unwrap();
    assert!(last_add < first_disable, "{log:?}");

    let tcp = m.backend().rule("PW-RDP-Allow").unwrap();
    assert_eq!(tcp.grouping, GROUP);
    assert_eq!(tcp.local_ports, "3389");
    assert_eq!(tcp.action, Action::Allow);
    assert!(tcp.remote_includes(ip("203.0.113.9")) && !tcp.remote_includes(ip("8.8.8.8")));
    assert!(!m.backend().rule("Remote Desktop - User Mode (TCP-In)").unwrap().enabled);
    // The shadow rule and unrelated rules are untouched.
    assert_eq!(
        m.backend().rule("Remote Desktop - Shadow (TCP-In)"),
        original.iter().find(|r| r.name == "Remote Desktop - Shadow (TCP-In)").cloned()
    );

    // The snapshot is plain data: store it, reload it, restore from the copy.
    let json = serde_json::to_string(&out.snapshot).unwrap();
    let snapshot: FirewallSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot, out.snapshot);
    m.backend().clear_log();
    let report = m.restore_snapshot(&snapshot).unwrap();
    assert_eq!(report.reenabled.len(), 2);
    assert_eq!(report.shield_removed, vec!["PW-RDP-Allow", "PW-RDP-Allow-UDP"]);
    let log = m.backend().writes();
    let last_enable = log.iter().rposition(|op| matches!(op, FakeOp::SetEnabled(_, true))).unwrap();
    let first_remove = log.iter().position(|op| matches!(op, FakeOp::Remove(_))).unwrap();
    assert!(last_enable < first_remove, "re-enable before removing the allow rules: {log:?}");
    assert_eq!(sorted(m.backend().rules()), original);

    // Restoring again changes nothing.
    m.backend().clear_log();
    let again = m.restore_snapshot(&snapshot).unwrap();
    assert_eq!(again, RestoreReport::default());
    assert!(m.backend().writes().is_empty());
}

const RDP_ALLOW_TCP_NAME: &str = "PW-RDP-Allow";
const RDP_ALLOW_UDP_NAME: &str = "PW-RDP-Allow-UDP";

#[test]
fn the_current_rdp_client_can_never_be_excluded() {
    let m = manager();
    let c = confirmation();
    let allowed = [cidr("203.0.113.0/24")];
    let err = m
        .rdp_restrict(
            &RdpRestrict {
                port: 3389,
                allowed: &allowed,
                required_clients: &[ip("203.0.113.5"), ip("198.51.100.9")],
                include_udp: false,
                disable_builtin: true,
            },
            1,
            &RuleOptions::default().confirmed(&c),
        )
        .unwrap_err();
    assert_eq!(err, FirewallError::RdpClientExcluded(vec![ip("198.51.100.9")]));
    assert!(m.backend().writes().is_empty());
    let err = m
        .rdp_restrict(
            &RdpRestrict {
                port: 3389,
                allowed: &[],
                required_clients: &[],
                include_udp: false,
                disable_builtin: true,
            },
            1,
            &RuleOptions::default().confirmed(&c),
        )
        .unwrap_err();
    assert_eq!(err, FirewallError::EmptyAllowList);
}

#[test]
fn builtin_rule_states_are_recorded_and_restorable() {
    let m = manager();
    let c = confirmation();
    // One built-in rule was already off before the shield.
    m.set_enabled(
        "Remote Desktop - User Mode (UDP-In)",
        false,
        &RuleOptions::default().foreign_edit().confirmed(&c),
    )
    .unwrap();
    let before = m.rdp_snapshot(5).unwrap();
    assert_eq!(before.rdp.builtin.iter().filter(|s| s.enabled).count(), 1);

    let prev = m.set_builtin_rdp_enabled(false, &RuleOptions::default().confirmed(&c)).unwrap();
    assert_eq!(prev, before.rdp.builtin);
    assert!(m.set_builtin_rdp_enabled(false, &RuleOptions::default()).is_ok(), "nothing left to disable");
    // Restoring the snapshot puts the already-off rule back OFF and the other one ON.
    m.restore_snapshot(&before).unwrap();
    assert!(m.backend().rule("Remote Desktop - User Mode (TCP-In)").unwrap().enabled);
    assert!(!m.backend().rule("Remote Desktop - User Mode (UDP-In)").unwrap().enabled);
    // Enabling all never needs a confirmation.
    m.set_builtin_rdp_enabled(true, &RuleOptions::default()).unwrap();
    assert!(m.backend().rule("Remote Desktop - User Mode (UDP-In)").unwrap().enabled);
}

#[test]
fn restore_with_a_vanished_builtin_rule_reports_it() {
    let m = manager();
    let mut snap = m.rdp_snapshot(1).unwrap();
    snap.rdp.builtin.push(RuleState {
        name: "Remote Desktop - Gone".into(),
        enabled: true,
    });
    let report = m.restore_snapshot(&snap).unwrap();
    assert_eq!(report.missing, vec!["Remote Desktop - Gone"]);
    snap.version = 99;
    assert!(matches!(m.restore_snapshot(&snap), Err(FirewallError::InvalidRule(_))));
}

// ---- listing -------------------------------------------------------------------------------

#[test]
fn listing_applies_filters() {
    let m = manager();
    let all = m.list_rules(&RuleFilter::default()).unwrap();
    assert_eq!(all.len(), 5);
    let rdp = m
        .list_rules(&RuleFilter {
            port: Some(3389),
            direction: Some(Direction::Inbound),
            enabled: Some(true),
            ..RuleFilter::default()
        })
        .unwrap();
    // TCP, UDP and the shadow rule (its ports are "*", so it applies to every port).
    assert_eq!(rdp.len(), 3);
    let by_text = m
        .list_rules(&RuleFilter {
            text: Some("printer".into()),
            ..RuleFilter::default()
        })
        .unwrap();
    assert_eq!(by_text.len(), 1);
    let none = CidrSet::new();
    m.block_ips(&BatchId::auto_block(), &[cidr("198.51.100.0/24")], &BlockOptions::new(&none)).unwrap();
    let hit = m
        .list_rules(&RuleFilter {
            group: Some(GROUP.into()),
            address: Some(ip("198.51.100.7")),
            ..RuleFilter::default()
        })
        .unwrap();
    assert_eq!(hit.len(), 1);
}

// ---- property-style ------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn step(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.step() % n
    }
}

#[test]
fn random_block_unblock_sequences_keep_the_firewall_consistent() {
    for seed in 1..=15u64 {
        let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
        let cap = 2 + rng.below(30) as usize;
        let m = FirewallManager::new(FakeFirewall::windows_defaults())
            .with_batch_config(BatchConfig::new(cap));
        let guard_set = protected(&["10.0.0.7", "10.0.1.0/28"]);
        let batch = BatchId::auto_block();
        let mut model: HashSet<Cidr> = HashSet::new();
        for _ in 0..60 {
            let n = 1 + rng.below(40) as u32;
            let start = rng.below(600) as u32;
            let list = hosts(start..start + n);
            match rng.below(3) {
                0 => {
                    let opts = BlockOptions::new(&guard_set).skip_protected();
                    m.block_ips(&batch, &list, &opts).unwrap();
                    model.extend(list.iter().copied().filter(|c| {
                        !guard_set.iter().any(|p| crate::addr::cidrs_overlap(p, c))
                    }));
                }
                1 => {
                    m.unblock_ips(&batch, &list).unwrap();
                    for c in &list {
                        model.remove(c);
                    }
                }
                _ => {
                    let opts = BlockOptions::new(&guard_set).skip_protected();
                    m.apply_blocklist(&batch, &list, &opts).unwrap();
                    model = list
                        .iter()
                        .copied()
                        .filter(|c| !guard_set.iter().any(|p| crate::addr::cidrs_overlap(p, c)))
                        .collect();
                }
            }
            let got: HashSet<Cidr> = m.list_blocks(&batch).unwrap().into_iter().collect();
            assert_eq!(got, model, "seed {seed}");
            let rules = pw_rules(&m);
            for r in &rules {
                let (addrs, junk) = r.remote_cidrs();
                assert_eq!(junk, 0);
                assert!(!addrs.is_empty() && addrs.len() <= cap, "seed {seed}");
                assert!(!r.remote_is_any());
            }
            assert!(rules.len() <= 2 * model.len().div_ceil(cap) + 1);
            for p in guard_set.iter() {
                assert!(!got.iter().any(|b| crate::addr::cidrs_overlap(b, p)));
            }
        }
        m.purge(&RuleOptions::default()).unwrap();
        assert!(pw_rules(&m).is_empty());
    }
}
