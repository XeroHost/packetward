// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Advanced MTR against scripted transports: probe modes, destination detection, route changes,
//! load balancing, silent hops, option clamping, enrichment, cancellation, IPv6.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pw_diag::fake::FakePinger;
use pw_diag::mtr_adv::{
    mtr_with, AdvMtrOptions, AdvMtrSnapshot, EnrichCache, FakeProbeTransport, HopEnricher, HopInfo,
    ModeUnavailable, MtrError, NoEnrich, PingerTransport, ProbeMode, ProbeReply, ProbeRequest,
    ProbeStatus, ProbeTransport, ReachKind, DEFAULT_UDP_PORT,
};
use pw_diag::{
    CancelToken, DiagError, EchoReply, EchoStatus, FnSink, NameCache, NullSink, ReverseLookup,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

const DEST: &str = "1.1.1.1";

fn opts(mode: ProbeMode, cycles: u32) -> AdvMtrOptions {
    AdvMtrOptions {
        mode,
        cycles,
        ..AdvMtrOptions::default()
    }
}

/// A route whose routers are `hops[0..]` (TTL 1..) and whose destination sits at
/// `hops.len() + 1`. Probes beyond reach the destination as well, answering `kind`.
fn straight(hops: Vec<&'static str>, kind: ReachKind) -> FakeProbeTransport {
    FakeProbeTransport::new(move |req, _| {
        let n = usize::from(req.ttl);
        if n <= hops.len() {
            Ok(ProbeReply::ttl_expired(
                ip(hops[n - 1]),
                ms(u64::from(req.ttl) * 5),
            ))
        } else {
            Ok(ProbeReply::reached(
                kind,
                req.target,
                ms((hops.len() as u64 + 1) * 5),
            ))
        }
    })
}

async fn run(
    transport: Arc<FakeProbeTransport>,
    target: &str,
    options: &AdvMtrOptions,
) -> Result<(AdvMtrSnapshot, Vec<AdvMtrSnapshot>), MtrError> {
    let mut seen = Vec::new();
    let mut sink = FnSink(|s: AdvMtrSnapshot| seen.push(s));
    let last = mtr_with(
        transport,
        ip(target),
        options,
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut sink,
    )
    .await?;
    Ok((last, seen))
}

#[tokio::test(start_paused = true)]
async fn icmp_mode_over_a_pinger_matches_the_simple_mtr() {
    let pinger = Arc::new(FakePinger::new(|req, _| {
        if req.ttl < 3 {
            Ok(EchoReply {
                status: EchoStatus::TtlExpired,
                from: Some(ip(&format!("10.0.0.{}", req.ttl))),
                rtt: Some(ms(7)),
                ttl: Some(60),
            })
        } else {
            Ok(EchoReply {
                status: EchoStatus::Success,
                from: Some(req.target),
                rtt: Some(ms(9)),
                ttl: Some(60),
            })
        }
    }));
    let transport = Arc::new(PingerTransport::new(pinger));
    let mut sink = NullSink;
    let last = mtr_with(
        transport,
        ip(DEST),
        &opts(ProbeMode::Icmp, 2),
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut sink,
    )
    .await
    .unwrap();
    assert_eq!(last.mode, ProbeMode::Icmp);
    assert_eq!(last.port, 0);
    assert!(last.destination_reached);
    assert_eq!(last.reached_via, Some(ReachKind::EchoReply));
    assert_eq!(last.hops.len(), 3);
    assert_eq!(last.cycle, 2);
    assert_eq!(last.to_trace().hops[2].addr, Some(ip(DEST)));
}

#[tokio::test(start_paused = true)]
async fn udp_mode_ends_on_port_unreachable() {
    let t = Arc::new(straight(
        vec!["192.168.1.1", "8.8.4.4"],
        ReachKind::PortUnreachable,
    ));
    let (last, seen) = run(Arc::clone(&t), DEST, &opts(ProbeMode::Udp, 3))
        .await
        .unwrap();
    assert_eq!(seen.len(), 3, "one snapshot per cycle");
    assert_eq!(last.mode, ProbeMode::Udp);
    assert_eq!(last.port, DEFAULT_UDP_PORT);
    assert!(last.destination_reached);
    assert_eq!(last.reached_via, Some(ReachKind::PortUnreachable));
    assert_eq!(last.hops.len(), 3);
    assert_eq!(last.hops[2].hop.addr, Some(ip(DEST)));
    for r in t.requests() {
        assert_eq!(r.mode, ProbeMode::Udp);
        assert_eq!(r.port, DEFAULT_UDP_PORT);
        assert_eq!(r.target, ip(DEST));
    }
    assert_eq!(t.prepared(), vec![(ProbeMode::Udp, ip(DEST))]);
}

#[tokio::test(start_paused = true)]
async fn udp_port_is_configurable_and_never_zero() {
    let t = Arc::new(straight(vec![], ReachKind::PortUnreachable));
    let o = AdvMtrOptions {
        udp_port: 40000,
        ..opts(ProbeMode::Udp, 1)
    };
    let (last, _) = run(Arc::clone(&t), DEST, &o).await.unwrap();
    assert_eq!(last.port, 40000);
    assert!(t.requests().iter().all(|r| r.port == 40000));

    let t = Arc::new(straight(vec![], ReachKind::PortUnreachable));
    let bad = AdvMtrOptions {
        udp_port: 0,
        ..opts(ProbeMode::Udp, 1)
    };
    let err = run(Arc::clone(&t), DEST, &bad).await.unwrap_err();
    assert!(matches!(err, MtrError::Diag(DiagError::InvalidInput(_))));
    let err = run(
        Arc::clone(&t),
        DEST,
        &opts(ProbeMode::TcpSyn { port: 0 }, 1),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, MtrError::Diag(DiagError::InvalidInput(_))));
    assert!(t.requests().is_empty(), "a zero port is never sent");
}

#[tokio::test(start_paused = true)]
async fn tcp_syn_destination_by_syn_ack_and_by_rst() {
    for kind in [ReachKind::SynAck, ReachKind::Rst] {
        let t = Arc::new(straight(vec!["192.168.1.1", "8.8.4.4", "9.9.9.9"], kind));
        let mode = ProbeMode::TcpSyn { port: 443 };
        let (last, _) = run(Arc::clone(&t), DEST, &opts(mode, 2)).await.unwrap();
        assert_eq!(last.mode, mode);
        assert_eq!(last.port, 443);
        assert!(last.destination_reached, "{kind:?}");
        assert_eq!(last.reached_via, Some(kind));
        assert_eq!(last.hops.len(), 4);
        assert!(t.requests().iter().all(|r| r.port == 443 && r.mode == mode));
    }
}

#[tokio::test(start_paused = true)]
async fn tcp_syn_reaches_a_host_that_drops_icmp() {
    // Routers answer time-exceeded, the destination only answers the SYN: the same script would
    // never end in ICMP mode, because the ICMP probe is dropped.
    let t = Arc::new(FakeProbeTransport::new(|req, _| match req.mode {
        ProbeMode::TcpSyn { .. } if req.ttl >= 3 => {
            Ok(ProbeReply::reached(ReachKind::SynAck, req.target, ms(12)))
        }
        ProbeMode::Icmp if req.ttl >= 3 => Ok(ProbeReply::timed_out()),
        _ => Ok(ProbeReply::ttl_expired(
            ip(&format!("10.1.0.{}", req.ttl)),
            ms(3),
        )),
    }));
    let o = AdvMtrOptions {
        max_hops: 6,
        ..opts(ProbeMode::Icmp, 1)
    };
    let (icmp, _) = run(Arc::clone(&t), DEST, &o).await.unwrap();
    assert!(!icmp.destination_reached);
    let o = AdvMtrOptions {
        mode: ProbeMode::TcpSyn { port: 443 },
        ..o
    };
    let (tcp, _) = run(t, DEST, &o).await.unwrap();
    assert!(tcp.destination_reached);
    assert_eq!(tcp.hops.len(), 3);
}

#[tokio::test(start_paused = true)]
async fn silent_hops_are_loss_and_the_trace_continues() {
    let t = Arc::new(FakeProbeTransport::new(|req, _| match req.ttl {
        2 => Ok(ProbeReply::timed_out()),
        1 | 3 => Ok(ProbeReply::ttl_expired(
            ip(&format!("10.2.0.{}", req.ttl)),
            ms(4),
        )),
        _ => Ok(ProbeReply::reached(
            ReachKind::PortUnreachable,
            req.target,
            ms(8),
        )),
    }));
    let (last, _) = run(t, DEST, &opts(ProbeMode::Udp, 3)).await.unwrap();
    assert!(last.destination_reached);
    assert_eq!(last.hops.len(), 4);
    let silent = &last.hops[1];
    assert_eq!(silent.hop.addr, None);
    assert_eq!(silent.hop.sent, 3);
    assert_eq!(silent.hop.received, 0);
    assert!((silent.hop.loss_percent - 100.0).abs() < 1e-9);
    assert!(silent.hop.rtt.is_none());
    assert!(silent.info.is_none());
}

#[tokio::test(start_paused = true)]
async fn route_change_updates_the_address_and_counts_the_change() {
    let t = Arc::new(FakeProbeTransport::new(|req, nth| {
        if req.ttl == 1 {
            let via = if nth < 2 { "10.3.0.1" } else { "10.3.0.99" };
            Ok(ProbeReply::ttl_expired(ip(via), ms(2)))
        } else {
            Ok(ProbeReply::reached(ReachKind::SynAck, req.target, ms(6)))
        }
    }));
    let mode = ProbeMode::TcpSyn { port: 22 };
    let (last, seen) = run(t, DEST, &opts(mode, 4)).await.unwrap();
    assert_eq!(seen[1].hops[0].hop.addr, Some(ip("10.3.0.1")));
    let hop = &last.hops[0].hop;
    assert_eq!(hop.addr, Some(ip("10.3.0.99")));
    assert_eq!(hop.other_addrs, vec![ip("10.3.0.1")]);
    assert_eq!(hop.address_changes, 1);
    assert_eq!(hop.received, 4, "statistics carry over the change");
}

#[tokio::test(start_paused = true)]
async fn load_balanced_hops_list_every_router() {
    let t = Arc::new(FakeProbeTransport::new(|req, nth| {
        if req.ttl == 2 {
            let via = ["10.4.0.1", "10.4.0.2", "10.4.0.3"][nth as usize % 3];
            Ok(ProbeReply::ttl_expired(ip(via), ms(5)))
        } else if req.ttl == 1 {
            Ok(ProbeReply::ttl_expired(ip("10.4.9.9"), ms(2)))
        } else {
            Ok(ProbeReply::reached(
                ReachKind::PortUnreachable,
                req.target,
                ms(9),
            ))
        }
    }));
    let (last, _) = run(t, DEST, &opts(ProbeMode::Udp, 6)).await.unwrap();
    let hop = &last.hops[1].hop;
    assert_eq!(hop.other_addrs.len(), 2);
    assert_eq!(hop.address_changes, 5);
    assert_eq!(hop.received, 6);
    assert_eq!(last.hops[0].hop.other_addrs.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn unreachable_destination_is_probed_to_max_hops_and_not_reached() {
    let t = Arc::new(FakeProbeTransport::new(|_, _| Ok(ProbeReply::timed_out())));
    let o = AdvMtrOptions {
        max_hops: 5,
        ..opts(ProbeMode::Udp, 1)
    };
    let (last, _) = run(t, DEST, &o).await.unwrap();
    assert!(!last.destination_reached);
    assert_eq!(last.reached_via, None);
    assert_eq!(last.hops.len(), 5);
}

#[tokio::test(start_paused = true)]
async fn option_clamps_apply_to_what_is_sent() {
    let t = Arc::new(straight(vec!["10.5.0.1"], ReachKind::PortUnreachable));
    let wild = AdvMtrOptions {
        mode: ProbeMode::Udp,
        cycles: 0,
        max_hops: 200,
        timeout: Duration::from_secs(3600),
        packet_size: u16::MAX,
        interval: Duration::ZERO,
        parallelism: 0,
        ..AdvMtrOptions::default()
    };
    let (last, seen) = run(Arc::clone(&t), DEST, &wild).await.unwrap();
    assert_eq!(seen.len(), 1, "zero cycles means one");
    assert_eq!(last.total_cycles, 1);
    let reqs = t.requests();
    assert!(reqs.iter().all(|r| r.timeout == Duration::from_secs(10)));
    assert!(reqs.iter().all(|r| r.payload_size == 1472));
    assert!(reqs.iter().all(|r| r.ttl <= 64));
    assert_eq!(
        reqs.len(),
        2,
        "parallelism 0 means 1: only TTL 1 and 2 were probed"
    );

    // Per-mode / per-family payload limits and the other bounds.
    let n = wild.normalized_for(ip(DEST));
    assert_eq!(n.max_hops, 64);
    assert_eq!(n.interval, ms(200));
    assert_eq!(n.parallelism, 1);
    assert_eq!(n.cycles, 1);
    assert_eq!(
        wild.normalized_for(ip("2606:4700:4700::1111")).packet_size,
        1452
    );
    let tcp = AdvMtrOptions {
        mode: ProbeMode::TcpSyn { port: 80 },
        ..wild.clone()
    };
    assert_eq!(tcp.normalized_for(ip(DEST)).packet_size, 0);
    let icmp = AdvMtrOptions {
        mode: ProbeMode::Icmp,
        ..wild.clone()
    };
    assert_eq!(icmp.normalized_for(ip(DEST)).packet_size, 1472);
    let big = AdvMtrOptions {
        cycles: 100_000,
        parallelism: 200,
        timeout: Duration::ZERO,
        ..AdvMtrOptions::default()
    };
    let n = big.normalized_for(ip(DEST));
    assert_eq!((n.cycles, n.parallelism), (1000, 16));
    assert_eq!(n.timeout, ms(1));
}

#[tokio::test(start_paused = true)]
async fn unavailable_modes_fail_before_anything_is_sent() {
    let t = Arc::new(
        straight(vec![], ReachKind::SynAck).with_unavailable(ModeUnavailable::new(
            ProbeMode::TcpSyn { port: 0 },
            "needs Npcap",
        )),
    );
    let err = run(
        Arc::clone(&t),
        DEST,
        &opts(ProbeMode::TcpSyn { port: 443 }, 1),
    )
    .await
    .unwrap_err();
    match err {
        MtrError::ModeUnavailable(m) => {
            assert!(matches!(m.mode, ProbeMode::TcpSyn { port: 443 }));
            assert_eq!(m.reason, "needs Npcap");
            assert_eq!(m.to_string(), "TCP SYN probes are unavailable: needs Npcap");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(t.requests().is_empty());
    // The other modes of the same transport still run.
    assert!(run(Arc::clone(&t), DEST, &opts(ProbeMode::Udp, 1))
        .await
        .is_ok());

    // A plain ICMP pinger cannot read UDP / TCP replies.
    let pinger = Arc::new(PingerTransport::new(Arc::new(FakePinger::new(|_, _| {
        Ok(EchoReply::timed_out())
    }))));
    let mut sink = NullSink;
    let err = mtr_with(
        pinger,
        ip(DEST),
        &opts(ProbeMode::Udp, 1),
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut sink,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, MtrError::ModeUnavailable(m) if m.mode == ProbeMode::Udp));
}

#[tokio::test(start_paused = true)]
async fn a_transport_that_cannot_send_is_an_error_not_a_silent_table() {
    let t = Arc::new(FakeProbeTransport::new(|_, _| {
        Err(DiagError::System {
            code: 5,
            message: "denied".to_owned(),
        }
        .into())
    }));
    let err = run(t, DEST, &opts(ProbeMode::Udp, 2)).await.unwrap_err();
    assert!(matches!(
        err,
        MtrError::Diag(DiagError::System { code: 5, .. })
    ));
}

struct Table {
    calls: AtomicUsize,
    asked: Mutex<Vec<IpAddr>>,
    data: HashMap<IpAddr, HopInfo>,
}

impl HopEnricher for Table {
    fn lookup(&self, ip: IpAddr) -> Option<HopInfo> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.asked.lock().unwrap().push(ip);
        self.data.get(&ip).cloned()
    }
}

#[tokio::test(start_paused = true)]
async fn enrichment_is_cached_and_never_looks_up_private_addresses() {
    let mut data = HashMap::new();
    data.insert(
        ip("8.8.4.4"),
        HopInfo {
            asn: Some(15169),
            as_org: Some("Google LLC".to_owned()),
            country_code: Some("US".to_owned()),
        },
    );
    data.insert(
        ip(DEST),
        HopInfo {
            asn: Some(13335),
            as_org: Some("Cloudflare, Inc.".to_owned()),
            country_code: Some("AU".to_owned()),
        },
    );
    // A private address that *would* have data if it were ever asked.
    data.insert(
        ip("192.168.1.1"),
        HopInfo {
            asn: Some(1),
            as_org: Some("must not appear".to_owned()),
            country_code: Some("ZZ".to_owned()),
        },
    );
    let table = Arc::new(Table {
        calls: AtomicUsize::new(0),
        asked: Mutex::new(Vec::new()),
        data,
    });
    let cache = EnrichCache::new(Arc::clone(&table));
    let t = Arc::new(straight(
        vec!["192.168.1.1", "10.9.0.1", "8.8.4.4", "100.64.0.7"],
        ReachKind::SynAck,
    ));
    let mut sink = NullSink;
    let o = opts(ProbeMode::TcpSyn { port: 443 }, 5);
    let last = mtr_with(
        Arc::clone(&t),
        ip(DEST),
        &o,
        &NameCache::disabled(),
        &cache,
        &CancelToken::new(),
        &mut sink,
    )
    .await
    .unwrap();
    assert_eq!(last.hops.len(), 5);
    assert_eq!(last.hops[0].info, None, "private");
    assert_eq!(last.hops[1].info, None, "private");
    assert_eq!(last.hops[3].info, None, "carrier-grade NAT space");
    assert_eq!(last.hops[2].asn_label().as_deref(), Some("AS15169"));
    assert_eq!(
        last.hops[4].info.as_ref().unwrap().country_code.as_deref(),
        Some("AU")
    );
    assert_eq!(
        table.calls.load(Ordering::SeqCst),
        2,
        "five cycles, two public addresses, two lookups"
    );
    let mut asked = table.asked.lock().unwrap().clone();
    asked.sort();
    assert_eq!(asked, vec![ip(DEST), ip("8.8.4.4")]);

    // A second run through the same cache costs nothing.
    mtr_with(
        t,
        ip(DEST),
        &o,
        &NameCache::disabled(),
        &cache,
        &CancelToken::new(),
        &mut NullSink,
    )
    .await
    .unwrap();
    assert_eq!(table.calls.load(Ordering::SeqCst), 2);
}

struct CountingNames(Arc<AtomicUsize>);

impl ReverseLookup for CountingNames {
    async fn reverse(&self, _ip: IpAddr) -> Option<String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Some("host.example.net".to_owned())
    }
}

#[tokio::test(start_paused = true)]
async fn do_not_resolve_names_never_touches_dns() {
    let counter = Arc::new(AtomicUsize::new(0));
    let names = NameCache::new(Arc::new(CountingNames(Arc::clone(&counter))), ms(500));
    let t = Arc::new(straight(vec!["8.8.4.4"], ReachKind::PortUnreachable));
    let mut sink = NullSink;
    let mut o = opts(ProbeMode::Udp, 2);
    o.resolve_names = false;
    let last = mtr_with(
        Arc::clone(&t),
        ip(DEST),
        &o,
        &names,
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut sink,
    )
    .await
    .unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert!(last.hops.iter().all(|h| h.hop.name.is_none()));

    o.resolve_names = true;
    let last = mtr_with(
        t,
        ip(DEST),
        &o,
        &names,
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut sink,
    )
    .await
    .unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 2, "two distinct addresses");
    assert_eq!(last.hops[0].hop.name.as_deref(), Some("host.example.net"));
}

#[tokio::test(start_paused = true)]
async fn cancel_between_cycles_returns_the_completed_cycles() {
    let t = Arc::new(straight(vec!["8.8.4.4"], ReachKind::SynAck));
    let cancel = CancelToken::new();
    let trigger = cancel.clone();
    let mut sink = FnSink(move |s: AdvMtrSnapshot| {
        if s.cycle == 2 {
            trigger.cancel();
        }
    });
    let last = mtr_with(
        t,
        ip(DEST),
        &opts(ProbeMode::TcpSyn { port: 443 }, 10),
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &cancel,
        &mut sink,
    )
    .await
    .unwrap();
    assert!(last.cancelled);
    assert_eq!(last.cycle, 2);
    assert_eq!(last.hops.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn cancel_mid_cycle_is_prompt_and_discards_the_cycle() {
    let t = Arc::new(
        FakeProbeTransport::new(|_, _| Ok(ProbeReply::timed_out()))
            .with_delay(Duration::from_secs(5)),
    );
    let cancel = CancelToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(ms(100)).await;
        trigger.cancel();
    });
    let started = tokio::time::Instant::now();
    let mut sink = NullSink;
    let last = mtr_with(
        t,
        ip(DEST),
        &opts(ProbeMode::Udp, 3),
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &cancel,
        &mut sink,
    )
    .await
    .unwrap();
    assert!(last.cancelled);
    assert_eq!(last.cycle, 0);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_dropped_receiver_stops_the_run() {
    let t = Arc::new(straight(vec!["8.8.4.4"], ReachKind::SynAck));
    let (mut tx, rx) = tokio::sync::mpsc::channel::<AdvMtrSnapshot>(1);
    drop(rx);
    let last = mtr_with(
        t,
        ip(DEST),
        &opts(ProbeMode::TcpSyn { port: 443 }, 10),
        &NameCache::disabled(),
        &EnrichCache::new(NoEnrich),
        &CancelToken::new(),
        &mut tx,
    )
    .await
    .unwrap();
    assert!(last.cancelled);
}

#[tokio::test(start_paused = true)]
async fn ipv6_trace_in_udp_and_tcp_modes() {
    let target = "2606:4700:4700::1111";
    for (mode, kind) in [
        (ProbeMode::Udp, ReachKind::PortUnreachable),
        (ProbeMode::TcpSyn { port: 443 }, ReachKind::SynAck),
    ] {
        let t = Arc::new(FakeProbeTransport::new(move |req, _| {
            if req.ttl < 3 {
                Ok(ProbeReply::ttl_expired(
                    ip(&format!("2001:4860:0:{:x}::1", req.ttl)),
                    ms(4),
                ))
            } else {
                Ok(ProbeReply::reached(kind, req.target, ms(11)))
            }
        }));
        let o = AdvMtrOptions {
            packet_size: 1500,
            ..opts(mode, 2)
        };
        let (last, _) = run(Arc::clone(&t), target, &o).await.unwrap();
        assert!(last.destination_reached);
        assert_eq!(last.family_label(), "IPv6");
        assert_eq!(last.hops[0].hop.addr, Some(ip("2001:4860:0:1::1")));
        assert_eq!(last.hops[2].hop.addr, Some(ip(target)));
        let want = if mode == ProbeMode::Udp { 1452 } else { 0 };
        assert!(t.requests().iter().all(|r| r.payload_size == want));
    }
}

#[tokio::test(start_paused = true)]
async fn the_run_future_is_send_so_the_engine_can_spawn_it() {
    let t = Arc::new(straight(vec!["8.8.4.4"], ReachKind::SynAck));
    let handle = tokio::spawn(async move {
        let mut sink = NullSink;
        mtr_with(
            t,
            ip(DEST),
            &opts(ProbeMode::TcpSyn { port: 443 }, 1),
            &NameCache::disabled(),
            &EnrichCache::new(NoEnrich),
            &CancelToken::new(),
            &mut sink,
        )
        .await
    });
    assert!(handle.await.unwrap().unwrap().destination_reached);
    // The transport trait objects the engine would hold are Send + Sync.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FakeProbeTransport>();
    assert_send_sync::<pw_diag::mtr_adv::SystemProbeTransport>();
    assert_send_sync::<EnrichCache<Arc<Table>>>();
}

#[test]
fn probe_replies_are_plain_data() {
    let r = ProbeReply::timed_out();
    assert_eq!(r.status, ProbeStatus::TimedOut);
    let req = ProbeRequest {
        target: ip(DEST),
        mode: ProbeMode::Udp,
        ttl: 3,
        payload_size: 0,
        port: 1,
        timeout: ms(1),
        seq: 1,
    };
    assert_eq!(req.clone(), req);
    // Only ICMP works without a capture backend.
    assert!(!ProbeMode::Icmp.needs_capture());
    assert!(ProbeMode::Udp.needs_capture());
    assert!(ProbeMode::TcpSyn { port: 1 }.needs_capture());
    // The default transport hook accepts everything.
    let fake = FakeProbeTransport::new(|_, _| Ok(ProbeReply::timed_out()));
    assert!(fake.prepare(ProbeMode::Udp, ip(DEST)).is_ok());
}
