// SPDX-License-Identifier: GPL-3.0-or-later
//! Exports of an [`AdvMtrSnapshot`]: the plain-text support report ("Copy report for support"),
//! CSV and JSON. All three are pure functions of their arguments (no clock, no locale, no
//! dependencies), so they can be compared byte for byte in tests. The simple
//! [`crate::format_report`] is unchanged.

use std::fmt::Write as _;
use std::net::IpAddr;

use super::AdvMtrSnapshot;
use crate::report::{format_utc, ReportContext};
use crate::stats::RttSummary;

/// The text of "Copy report for support": a header (target, mode, timestamp, source public IP
/// when known, cycles, result) and a table with ASN and country columns. Host names and network
/// names are stripped of control characters so a hostile PTR record cannot forge report lines.
pub fn support_report(snapshot: &AdvMtrSnapshot, ctx: &ReportContext) -> String {
    let mut out = String::new();
    out.push_str("PacketWard MTR report\n");
    let _ = writeln!(out, "Target: {}", target_text(snapshot.target, &ctx.target));
    let _ = writeln!(
        out,
        "Mode: {}, {}",
        snapshot.mode_description(),
        snapshot.family_label()
    );
    let _ = writeln!(out, "Generated: {}", format_utc(ctx.generated_at));
    if let Some(ip) = ctx.source_public_ip {
        let _ = writeln!(out, "Source public IP: {ip}");
    }
    let _ = writeln!(
        out,
        "Cycles: {} of {}",
        snapshot.cycle, snapshot.total_cycles
    );
    let result = match (snapshot.destination_reached, snapshot.reached_via) {
        (true, Some(via)) => format!("destination reached ({})", via.label()),
        (true, None) => "destination reached".to_owned(),
        (false, _) => "destination not reached".to_owned(),
    };
    let _ = writeln!(out, "Result: {result}");
    if snapshot.cancelled {
        out.push_str("Note: cancelled before all cycles finished\n");
    }
    out.push('\n');

    const COLS: usize = 13;
    let header: [String; COLS] = [
        "Hop", "Host", "ASN", "CC", "Loss%", "Sent", "Last", "Avg", "Best", "Wrst", "StDev",
        "Jitter", "Network",
    ]
    .map(str::to_owned);
    // Host, ASN, CC and Network are text (left aligned); the rest are numbers.
    let left = |i: usize| matches!(i, 1 | 2 | 3 | 12);

    let mut rows: Vec<[String; COLS]> = Vec::new();
    let mut extras: Vec<Vec<String>> = Vec::new();
    for h in &snapshot.hops {
        let hop = &h.hop;
        let host = match (&hop.name, hop.addr) {
            (Some(name), Some(addr)) => format!("{} ({addr})", clean(name)),
            (None, Some(addr)) => addr.to_string(),
            (_, None) => "???".to_owned(),
        };
        let info = h.info.as_ref();
        let ms = |f: fn(&RttSummary) -> f64| {
            hop.rtt
                .as_ref()
                .map_or_else(|| "-".to_owned(), |r| format!("{:.1}", f(r)))
        };
        rows.push([
            hop.ttl.to_string(),
            host,
            h.asn_label().unwrap_or_else(|| "-".to_owned()),
            info.and_then(|i| i.country_code.as_deref())
                .map_or_else(|| "-".to_owned(), clean),
            format!("{:.1}", hop.loss_percent),
            hop.sent.to_string(),
            ms(|r| r.last_ms),
            ms(|r| r.avg_ms),
            ms(|r| r.min_ms),
            ms(|r| r.max_ms),
            ms(|r| r.stddev_ms),
            ms(|r| r.jitter_ms),
            info.and_then(|i| i.as_org.as_deref())
                .map_or_else(|| "-".to_owned(), clean),
        ]);
        extras.push(hop.other_addrs.iter().map(IpAddr::to_string).collect());
    }

    let mut widths: [usize; COLS] = std::array::from_fn(|i| header[i].chars().count());
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    push_line(&mut out, &header, &widths, left);
    for (row, extra) in rows.iter().zip(&extras) {
        push_line(&mut out, row, &widths, left);
        for addr in extra {
            let pad = " ".repeat(widths[0] + 2);
            let _ = writeln!(out, "{pad}+- {addr}");
        }
    }
    out
}

fn push_line<const N: usize>(
    out: &mut String,
    cells: &[String; N],
    widths: &[usize; N],
    left: impl Fn(usize) -> bool,
) {
    let mut line = String::new();
    for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        let pad = " ".repeat(width.saturating_sub(cell.chars().count()));
        if left(i) {
            line.push_str(cell);
            line.push_str(&pad);
        } else {
            line.push_str(&pad);
            line.push_str(cell);
        }
    }
    out.push_str(line.trim_end());
    out.push('\n');
}

fn target_text(target: IpAddr, typed: &str) -> String {
    let ip_text = target.to_string();
    let typed = clean(typed.trim());
    if typed.is_empty() || typed == ip_text {
        ip_text
    } else {
        format!("{typed} ({ip_text})")
    }
}

/// Replace control characters (and line separators) by `?`.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn ms_opt(rtt: Option<&RttSummary>, f: fn(&RttSummary) -> f64, null: &str) -> String {
    match rtt.map(f) {
        Some(v) if v.is_finite() => format!("{v:.3}"),
        _ => null.to_owned(),
    }
}

/// One CSV field: quoted when it contains a comma, quote or line break. Text that a spreadsheet
/// would read as a formula (`=`, `+`, `-`, `@` first) is prefixed with `'`.
fn csv_text(s: &str) -> String {
    let mut text = clean(s);
    if text.starts_with(['=', '+', '-', '@']) {
        text.insert(0, '\'');
    }
    if text.contains([',', '"']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

/// CSV with one row per hop (header first, `\n` line ends, empty cells for unknown values):
/// `hop,address,hostname,asn,as_org,country,loss_percent,sent,received,last_ms,avg_ms,best_ms,
/// worst_ms,stddev_ms,jitter_ms,address_changes,other_addresses` (other addresses are separated by
/// spaces).
pub fn to_csv(snapshot: &AdvMtrSnapshot) -> String {
    let mut out = String::from(
        "hop,address,hostname,asn,as_org,country,loss_percent,sent,received,last_ms,avg_ms,\
         best_ms,worst_ms,stddev_ms,jitter_ms,address_changes,other_addresses\n",
    );
    for h in &snapshot.hops {
        let hop = &h.hop;
        let info = h.info.as_ref();
        let rtt = hop.rtt.as_ref();
        let cells = [
            hop.ttl.to_string(),
            hop.addr.map(|a| a.to_string()).unwrap_or_default(),
            hop.name.as_deref().map(csv_text).unwrap_or_default(),
            info.and_then(|i| i.asn)
                .map(|n| n.to_string())
                .unwrap_or_default(),
            info.and_then(|i| i.as_org.as_deref())
                .map(csv_text)
                .unwrap_or_default(),
            info.and_then(|i| i.country_code.as_deref())
                .map(csv_text)
                .unwrap_or_default(),
            format!("{:.1}", hop.loss_percent),
            hop.sent.to_string(),
            hop.received.to_string(),
            ms_opt(rtt, |r| r.last_ms, ""),
            ms_opt(rtt, |r| r.avg_ms, ""),
            ms_opt(rtt, |r| r.min_ms, ""),
            ms_opt(rtt, |r| r.max_ms, ""),
            ms_opt(rtt, |r| r.stddev_ms, ""),
            ms_opt(rtt, |r| r.jitter_ms, ""),
            hop.address_changes.to_string(),
            hop.other_addrs
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        ];
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

/// A JSON string literal, ASCII only: quotes, backslashes, control characters and everything
/// above U+007E are escaped.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

fn json_opt_str(s: Option<&str>) -> String {
    s.map_or_else(|| "null".to_owned(), json_str)
}

fn json_opt_num<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "null".to_owned(), |v| v.to_string())
}

/// `2023-11-14T22:13:20Z` from the report timestamp.
fn iso_utc(t: std::time::SystemTime) -> String {
    let text = format_utc(t);
    let core = text.strip_suffix(" UTC").unwrap_or(&text);
    format!("{}Z", core.replacen(' ', "T", 1))
}

/// Pretty-printed JSON (2-space indent, ASCII only, `null` for unknown values, three decimals for
/// milliseconds; numbers are never `NaN`/`inf`). Top-level keys: `tool`, `format_version`,
/// `generated_at`, `target`, `target_ip`, `ip_version`, `mode` (`icmp` / `udp` / `tcp_syn`),
/// `port`, `source_public_ip`, `cycle`, `total_cycles`, `destination_reached`, `reached_via`,
/// `cancelled`, `hops`.
pub fn to_json(snapshot: &AdvMtrSnapshot, ctx: &ReportContext) -> String {
    let mode = match snapshot.mode {
        super::ProbeMode::Icmp => "icmp",
        super::ProbeMode::Udp => "udp",
        super::ProbeMode::TcpSyn { .. } => "tcp_syn",
    };
    let ip_text = snapshot.target.to_string();
    let typed = ctx.target.trim();
    let typed = if typed.is_empty() { &ip_text } else { typed };
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"tool\": \"PacketWard\",");
    let _ = writeln!(out, "  \"format_version\": 1,");
    let _ = writeln!(
        out,
        "  \"generated_at\": \"{}\",",
        iso_utc(ctx.generated_at)
    );
    let _ = writeln!(out, "  \"target\": {},", json_str(typed));
    let _ = writeln!(out, "  \"target_ip\": {},", json_str(&ip_text));
    let _ = writeln!(
        out,
        "  \"ip_version\": {},",
        if snapshot.target.is_ipv6() { 6 } else { 4 }
    );
    let _ = writeln!(out, "  \"mode\": \"{mode}\",");
    let port = (snapshot.port != 0).then_some(snapshot.port);
    let _ = writeln!(out, "  \"port\": {},", json_opt_num(port));
    let source = ctx.source_public_ip.map(|ip| ip.to_string());
    let _ = writeln!(
        out,
        "  \"source_public_ip\": {},",
        json_opt_str(source.as_deref())
    );
    let _ = writeln!(out, "  \"cycle\": {},", snapshot.cycle);
    let _ = writeln!(out, "  \"total_cycles\": {},", snapshot.total_cycles);
    let _ = writeln!(
        out,
        "  \"destination_reached\": {},",
        snapshot.destination_reached
    );
    let _ = writeln!(
        out,
        "  \"reached_via\": {},",
        json_opt_str(snapshot.reached_via.map(super::ReachKind::label))
    );
    let _ = writeln!(out, "  \"cancelled\": {},", snapshot.cancelled);
    if snapshot.hops.is_empty() {
        out.push_str("  \"hops\": []\n}\n");
        return out;
    }
    out.push_str("  \"hops\": [\n");
    for (i, h) in snapshot.hops.iter().enumerate() {
        let hop = &h.hop;
        let info = h.info.as_ref();
        let rtt = hop.rtt.as_ref();
        let addr = hop.addr.map(|a| a.to_string());
        let others = hop
            .other_addrs
            .iter()
            .map(|a| json_str(&a.to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        let loss = if hop.loss_percent.is_finite() {
            format!("{:.1}", hop.loss_percent)
        } else {
            "null".to_owned()
        };
        out.push_str("    {\n");
        let _ = writeln!(out, "      \"ttl\": {},", hop.ttl);
        let _ = writeln!(out, "      \"address\": {},", json_opt_str(addr.as_deref()));
        let _ = writeln!(
            out,
            "      \"hostname\": {},",
            json_opt_str(hop.name.as_deref())
        );
        let _ = writeln!(
            out,
            "      \"asn\": {},",
            json_opt_num(info.and_then(|i| i.asn))
        );
        let _ = writeln!(
            out,
            "      \"as_org\": {},",
            json_opt_str(info.and_then(|i| i.as_org.as_deref()))
        );
        let _ = writeln!(
            out,
            "      \"country\": {},",
            json_opt_str(info.and_then(|i| i.country_code.as_deref()))
        );
        let _ = writeln!(out, "      \"loss_percent\": {loss},");
        let _ = writeln!(out, "      \"sent\": {},", hop.sent);
        let _ = writeln!(out, "      \"received\": {},", hop.received);
        let _ = writeln!(
            out,
            "      \"last_ms\": {},",
            ms_opt(rtt, |r| r.last_ms, "null")
        );
        let _ = writeln!(
            out,
            "      \"avg_ms\": {},",
            ms_opt(rtt, |r| r.avg_ms, "null")
        );
        let _ = writeln!(
            out,
            "      \"best_ms\": {},",
            ms_opt(rtt, |r| r.min_ms, "null")
        );
        let _ = writeln!(
            out,
            "      \"worst_ms\": {},",
            ms_opt(rtt, |r| r.max_ms, "null")
        );
        let _ = writeln!(
            out,
            "      \"stddev_ms\": {},",
            ms_opt(rtt, |r| r.stddev_ms, "null")
        );
        let _ = writeln!(
            out,
            "      \"jitter_ms\": {},",
            ms_opt(rtt, |r| r.jitter_ms, "null")
        );
        let _ = writeln!(out, "      \"address_changes\": {},", hop.address_changes);
        let _ = writeln!(out, "      \"other_addresses\": [{others}]");
        out.push_str(if i + 1 == snapshot.hops.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    out.push_str("  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings_are_escaped_and_ascii() {
        assert_eq!(json_str("a\"b\\c\n\t\u{1}"), "\"a\\\"b\\\\c\\n\\t\\u0001\"");
        assert_eq!(json_str("caf\u{e9}"), "\"caf\\u00e9\"");
        assert_eq!(json_str("\u{1F600}"), "\"\\ud83d\\ude00\"");
    }

    #[test]
    fn csv_fields_are_quoted_and_defused() {
        assert_eq!(csv_text("Cloudflare, Inc."), "\"Cloudflare, Inc.\"");
        assert_eq!(csv_text("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_text("=cmd()"), "'=cmd()");
        assert_eq!(csv_text("a\nb"), "a?b");
        assert_eq!(csv_text("plain"), "plain");
    }

    #[test]
    fn iso_timestamp() {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(iso_utc(t), "2023-11-14T22:13:20Z");
    }
}
