// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Golden outputs of the advanced MTR exports (support report, CSV, JSON). Expected texts are
//! inline literals so they compare byte for byte whatever the checkout's line-ending settings.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;
use std::time::{Duration, UNIX_EPOCH};

use pw_diag::mtr::{HopSnapshot, MtrSnapshot};
use pw_diag::mtr_adv::export::{support_report, to_csv, to_json};
use pw_diag::mtr_adv::{AdvHop, AdvMtrSnapshot, HopInfo, ProbeMode, ReachKind};
use pw_diag::{ReportContext, RttSummary};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn rtt(last: f64, avg: f64, best: f64, worst: f64, sd: f64, jit: f64) -> Option<RttSummary> {
    Some(RttSummary {
        count: 10,
        last_ms: last,
        min_ms: best,
        avg_ms: avg,
        max_ms: worst,
        stddev_ms: sd,
        jitter_ms: jit,
    })
}

fn info(asn: u32, org: &str, cc: &str) -> Option<HopInfo> {
    Some(HopInfo {
        asn: Some(asn),
        as_org: Some(org.to_owned()),
        country_code: Some(cc.to_owned()),
    })
}

fn ctx(source: Option<&str>) -> ReportContext {
    ReportContext {
        source_public_ip: source.map(ip),
        generated_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        target: "one.one.one.one".to_owned(),
    }
}

fn snapshot() -> AdvMtrSnapshot {
    AdvMtrSnapshot {
        mode: ProbeMode::Udp,
        port: 33434,
        target: ip("1.1.1.1"),
        cycle: 10,
        total_cycles: 10,
        hops: vec![
            AdvHop {
                hop: HopSnapshot {
                    ttl: 1,
                    addr: Some(ip("192.168.1.1")),
                    other_addrs: vec![],
                    name: Some("gw.lan".to_owned()),
                    sent: 10,
                    received: 10,
                    loss_percent: 0.0,
                    rtt: rtt(0.8, 0.9, 0.7, 1.5, 0.2, 0.1),
                    address_changes: 0,
                },
                info: None,
            },
            AdvHop {
                hop: HopSnapshot {
                    ttl: 2,
                    addr: None,
                    other_addrs: vec![],
                    name: None,
                    sent: 10,
                    received: 0,
                    loss_percent: 100.0,
                    rtt: None,
                    address_changes: 0,
                },
                info: None,
            },
            AdvHop {
                hop: HopSnapshot {
                    ttl: 3,
                    addr: Some(ip("8.8.4.4")),
                    other_addrs: vec![ip("8.8.8.8")],
                    name: None,
                    sent: 10,
                    received: 9,
                    loss_percent: 10.0,
                    rtt: rtt(12.25, 11.5, 9.75, 20.0, 3.125, 2.0),
                    address_changes: 4,
                },
                info: info(15169, "Google LLC", "US"),
            },
            AdvHop {
                hop: HopSnapshot {
                    ttl: 4,
                    addr: Some(ip("1.1.1.1")),
                    other_addrs: vec![],
                    name: Some("one.one.one.one".to_owned()),
                    sent: 10,
                    received: 10,
                    loss_percent: 0.0,
                    rtt: rtt(14.0, 14.5, 13.0, 18.25, 1.5, 1.0),
                    address_changes: 0,
                },
                info: info(13335, "Cloudflare, Inc.", "AU"),
            },
        ],
        destination_reached: true,
        reached_via: Some(ReachKind::PortUnreachable),
        cancelled: false,
    }
}

/// Strip the newline that follows the opening quote of a raw string literal.
fn body(s: &str) -> &str {
    s.strip_prefix('\n').unwrap_or(s)
}

const REPORT: &str = r#"
PacketWard MTR report
Target: one.one.one.one (1.1.1.1)
Mode: UDP (port 33434), IPv4
Generated: 2023-11-14 22:13:20 UTC
Source public IP: 203.0.113.5
Cycles: 10 of 10
Result: destination reached (port-unreachable)

Hop  Host                       ASN      CC  Loss%  Sent  Last   Avg  Best  Wrst  StDev  Jitter  Network
  1  gw.lan (192.168.1.1)       -        -     0.0    10   0.8   0.9   0.7   1.5    0.2     0.1  -
  2  ???                        -        -   100.0    10     -     -     -     -      -       -  -
  3  8.8.4.4                    AS15169  US   10.0    10  12.2  11.5   9.8  20.0    3.1     2.0  Google LLC
     +- 8.8.8.8
  4  one.one.one.one (1.1.1.1)  AS13335  AU    0.0    10  14.0  14.5  13.0  18.2    1.5     1.0  Cloudflare, Inc.
"#;

const CSV: &str = r#"
hop,address,hostname,asn,as_org,country,loss_percent,sent,received,last_ms,avg_ms,best_ms,worst_ms,stddev_ms,jitter_ms,address_changes,other_addresses
1,192.168.1.1,gw.lan,,,,0.0,10,10,0.800,0.900,0.700,1.500,0.200,0.100,0,
2,,,,,,100.0,10,0,,,,,,,0,
3,8.8.4.4,,15169,Google LLC,US,10.0,10,9,12.250,11.500,9.750,20.000,3.125,2.000,4,8.8.8.8
4,1.1.1.1,one.one.one.one,13335,"Cloudflare, Inc.",AU,0.0,10,10,14.000,14.500,13.000,18.250,1.500,1.000,0,
"#;

const JSON: &str = r#"
{
  "tool": "PacketWard",
  "format_version": 1,
  "generated_at": "2023-11-14T22:13:20Z",
  "target": "one.one.one.one",
  "target_ip": "1.1.1.1",
  "ip_version": 4,
  "mode": "udp",
  "port": 33434,
  "source_public_ip": "203.0.113.5",
  "cycle": 10,
  "total_cycles": 10,
  "destination_reached": true,
  "reached_via": "port-unreachable",
  "cancelled": false,
  "hops": [
    {
      "ttl": 1,
      "address": "192.168.1.1",
      "hostname": "gw.lan",
      "asn": null,
      "as_org": null,
      "country": null,
      "loss_percent": 0.0,
      "sent": 10,
      "received": 10,
      "last_ms": 0.800,
      "avg_ms": 0.900,
      "best_ms": 0.700,
      "worst_ms": 1.500,
      "stddev_ms": 0.200,
      "jitter_ms": 0.100,
      "address_changes": 0,
      "other_addresses": []
    },
    {
      "ttl": 2,
      "address": null,
      "hostname": null,
      "asn": null,
      "as_org": null,
      "country": null,
      "loss_percent": 100.0,
      "sent": 10,
      "received": 0,
      "last_ms": null,
      "avg_ms": null,
      "best_ms": null,
      "worst_ms": null,
      "stddev_ms": null,
      "jitter_ms": null,
      "address_changes": 0,
      "other_addresses": []
    },
    {
      "ttl": 3,
      "address": "8.8.4.4",
      "hostname": null,
      "asn": 15169,
      "as_org": "Google LLC",
      "country": "US",
      "loss_percent": 10.0,
      "sent": 10,
      "received": 9,
      "last_ms": 12.250,
      "avg_ms": 11.500,
      "best_ms": 9.750,
      "worst_ms": 20.000,
      "stddev_ms": 3.125,
      "jitter_ms": 2.000,
      "address_changes": 4,
      "other_addresses": ["8.8.8.8"]
    },
    {
      "ttl": 4,
      "address": "1.1.1.1",
      "hostname": "one.one.one.one",
      "asn": 13335,
      "as_org": "Cloudflare, Inc.",
      "country": "AU",
      "loss_percent": 0.0,
      "sent": 10,
      "received": 10,
      "last_ms": 14.000,
      "avg_ms": 14.500,
      "best_ms": 13.000,
      "worst_ms": 18.250,
      "stddev_ms": 1.500,
      "jitter_ms": 1.000,
      "address_changes": 0,
      "other_addresses": []
    }
  ]
}
"#;

#[test]
fn support_report_golden() {
    let text = support_report(&snapshot(), &ctx(Some("203.0.113.5")));
    assert_eq!(text, body(REPORT));
    assert!(
        text.lines().all(|l| l == l.trim_end()),
        "no trailing spaces"
    );
}

#[test]
fn support_report_omits_the_source_ip_line_when_unknown() {
    let text = support_report(&snapshot(), &ctx(None));
    assert!(!text.contains("Source public IP"));
    assert!(text.contains("Generated: 2023-11-14 22:13:20 UTC"));
}

#[test]
fn csv_golden() {
    assert_eq!(to_csv(&snapshot()), body(CSV));
}

#[test]
fn json_golden() {
    assert_eq!(to_json(&snapshot(), &ctx(Some("203.0.113.5"))), body(JSON));
}

#[test]
fn json_without_source_ip_has_null() {
    let text = to_json(&snapshot(), &ctx(None));
    assert!(text.contains("\"source_public_ip\": null,"));
}

#[test]
fn icmp_and_tcp_modes_are_labelled() {
    let mut s = snapshot();
    s.mode = ProbeMode::Icmp;
    s.port = 0;
    s.reached_via = Some(ReachKind::EchoReply);
    let text = support_report(&s, &ctx(None));
    assert!(text.contains("Mode: ICMP, IPv4\n"));
    assert!(text.contains("Result: destination reached (echo-reply)\n"));
    let json = to_json(&s, &ctx(None));
    assert!(json.contains("\"mode\": \"icmp\",\n  \"port\": null,"));

    s.mode = ProbeMode::TcpSyn { port: 443 };
    s.port = 443;
    s.reached_via = Some(ReachKind::Rst);
    let text = support_report(&s, &ctx(None));
    assert!(text.contains("Mode: TCP SYN (port 443), IPv4\n"));
    assert!(text.contains("Result: destination reached (rst)\n"));
    assert!(to_json(&s, &ctx(None)).contains("\"mode\": \"tcp_syn\",\n  \"port\": 443,"));
}

#[test]
fn unreached_and_cancelled_are_stated() {
    let mut s = snapshot();
    s.destination_reached = false;
    s.reached_via = None;
    s.cancelled = true;
    s.cycle = 3;
    let text = support_report(&s, &ctx(None));
    assert!(text.contains("Cycles: 3 of 10\n"));
    assert!(text.contains("Result: destination not reached\n"));
    assert!(text.contains("Note: cancelled"));
    let json = to_json(&s, &ctx(None));
    assert!(json.contains("\"destination_reached\": false,"));
    assert!(json.contains("\"reached_via\": null,"));
    assert!(json.contains("\"cancelled\": true,"));
}

#[test]
fn ipv6_addresses_are_formatted_in_all_three_exports() {
    let hop = |ttl: u8, addr: &str, other: Option<&str>| AdvHop {
        hop: HopSnapshot {
            ttl,
            addr: Some(ip(addr)),
            other_addrs: other.map(ip).into_iter().collect(),
            name: None,
            sent: 4,
            received: 4,
            loss_percent: 0.0,
            rtt: rtt(5.0, 5.0, 5.0, 5.0, 0.0, 0.0),
            address_changes: 0,
        },
        info: info(15169, "Google LLC", "US"),
    };
    let s = AdvMtrSnapshot {
        mode: ProbeMode::TcpSyn { port: 443 },
        port: 443,
        target: ip("2606:4700:4700::1111"),
        cycle: 4,
        total_cycles: 4,
        hops: vec![
            hop(1, "2001:4860:0:1::1", Some("2001:4860:0:1::2")),
            hop(2, "2606:4700:4700::1111", None),
        ],
        destination_reached: true,
        reached_via: Some(ReachKind::SynAck),
        cancelled: false,
    };
    let c = ReportContext {
        target: "2606:4700:4700::1111".to_owned(),
        ..ctx(Some("2001:db8::7"))
    };
    let text = support_report(&s, &c);
    assert!(text.contains("Target: 2606:4700:4700::1111\n"), "{text}");
    assert!(text.contains("Mode: TCP SYN (port 443), IPv6\n"));
    assert!(text.contains("Source public IP: 2001:db8::7\n"));
    assert!(text.contains("  1  2001:4860:0:1::1"));
    assert!(text.contains("     +- 2001:4860:0:1::2\n"));
    let csv = to_csv(&s);
    assert!(csv.contains("\n1,2001:4860:0:1::1,,15169,Google LLC,US,"));
    assert!(csv.contains(",0,2001:4860:0:1::2\n"));
    let json = to_json(&s, &c);
    assert!(json.contains("\"ip_version\": 6,"));
    assert!(json.contains("\"address\": \"2001:4860:0:1::1\","));
    assert!(json.contains("\"other_addresses\": [\"2001:4860:0:1::2\"]"));
    assert!(json.contains("\"source_public_ip\": \"2001:db8::7\","));
}

#[test]
fn hostile_names_cannot_forge_lines_or_break_the_formats() {
    let mut s = snapshot();
    s.hops[0].hop.name = Some("evil\nHop  9  forged\u{7}".to_owned());
    s.hops[2].info = info(15169, "=HYPERLINK(\"x\"), \"Inc\"\r\nline", "U\u{e9}");
    let text = support_report(&s, &ctx(None));
    assert!(!text.contains("\nHop  9"));
    assert_eq!(text.lines().count(), 13, "{text}");
    let csv = to_csv(&s);
    assert_eq!(csv.lines().count(), 5, "{csv}");
    assert!(csv.contains("\"'=HYPERLINK(\"\"x\"\"), \"\"Inc\"\"??line\""));
    let json = to_json(&s, &ctx(None));
    assert!(json.is_ascii());
    assert!(json.contains("\"evil\\nHop  9  forged\\u0007\""));
    assert!(json.contains("\"U\\u00e9\""));
    assert!(json.contains("\\r\\nline"));
}

#[test]
fn trace_downgrade_keeps_the_simple_table() {
    let s = snapshot();
    let t: MtrSnapshot = s.to_trace();
    assert_eq!(t.hops.len(), 4);
    assert_eq!(t.hops[2].other_addrs, vec![ip("8.8.8.8")]);
    assert!(t.destination_reached && !t.cancelled);
}

#[test]
fn empty_table_exports() {
    let mut s = snapshot();
    s.hops.clear();
    s.cycle = 0;
    s.destination_reached = false;
    s.reached_via = None;
    assert!(to_json(&s, &ctx(None)).ends_with("\"hops\": []\n}\n"));
    assert_eq!(to_csv(&s).lines().count(), 1);
    assert!(support_report(&s, &ctx(None)).contains("Hop  Host"));
}
