// SPDX-License-Identifier: GPL-3.0-or-later
//! "Copy report for support": a deterministic plain-text rendering of an MTR table.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mtr::{HopSnapshot, MtrSnapshot};

/// Everything the report needs besides the table itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportContext {
    /// This machine's public IP as seen from outside; the line is omitted when `None`.
    pub source_public_ip: Option<IpAddr>,
    /// When the report is generated (rendered in UTC).
    pub generated_at: SystemTime,
    /// The target as the user typed it (host name or address).
    pub target: String,
}

/// Render `snapshot` as a plain-text table preceded by a small header. The output depends only on
/// the arguments (no clock, no locale), so it can be compared byte for byte in tests.
pub fn format_report(snapshot: &MtrSnapshot, ctx: &ReportContext) -> String {
    let mut out = String::new();
    out.push_str("PacketWard MTR report\n");

    let ip_text = snapshot.target.to_string();
    let target = if ctx.target.trim().is_empty() || ctx.target.trim() == ip_text {
        ip_text
    } else {
        format!("{} ({})", ctx.target.trim(), ip_text)
    };
    out.push_str(&format!("Target: {target}\n"));
    out.push_str(&format!("Generated: {}\n", format_utc(ctx.generated_at)));
    if let Some(ip) = ctx.source_public_ip {
        out.push_str(&format!("Source public IP: {ip}\n"));
    }
    out.push_str(&format!(
        "Cycles: {} of {}\n",
        snapshot.cycle, snapshot.total_cycles
    ));
    let status = if snapshot.destination_reached {
        "destination reached"
    } else {
        "destination not reached"
    };
    out.push_str(&format!("Result: {status}\n\n"));

    let header = [
        "Hop", "Host", "Loss%", "Sent", "Last", "Avg", "Best", "Wrst", "StDev", "Jitter",
    ];
    let mut rows: Vec<[String; 10]> = Vec::new();
    let mut extras: Vec<Vec<String>> = Vec::new();
    for hop in &snapshot.hops {
        rows.push(row_for(hop));
        extras.push(hop.other_addrs.iter().map(IpAddr::to_string).collect());
    }

    let mut widths = header.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row.iter()) {
            *w = (*w).max(cell.chars().count());
        }
    }

    push_line(&mut out, &header.map(str::to_owned), &widths);
    for (row, extra) in rows.iter().zip(&extras) {
        push_line(&mut out, row, &widths);
        for addr in extra {
            let pad = " ".repeat(widths[0] + 2);
            out.push_str(&format!("{pad}+- {addr}\n"));
        }
    }
    out
}

fn row_for(hop: &HopSnapshot) -> [String; 10] {
    let host = match (&hop.name, hop.addr) {
        (Some(name), Some(addr)) => format!("{name} ({addr})"),
        (None, Some(addr)) => addr.to_string(),
        (_, None) => "???".to_owned(),
    };
    let ms = |f: fn(&crate::stats::RttSummary) -> f64| {
        hop.rtt
            .as_ref()
            .map_or_else(|| "-".to_owned(), |r| format!("{:.1}", f(r)))
    };
    [
        hop.ttl.to_string(),
        host,
        format!("{:.1}", hop.loss_percent),
        hop.sent.to_string(),
        ms(|r| r.last_ms),
        ms(|r| r.avg_ms),
        ms(|r| r.min_ms),
        ms(|r| r.max_ms),
        ms(|r| r.stddev_ms),
        ms(|r| r.jitter_ms),
    ]
}

/// Hop number and host are left-aligned, every numeric column right-aligned.
fn push_line(out: &mut String, cells: &[String; 10], widths: &[usize; 10]) {
    let mut line = String::new();
    for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        let len = cell.chars().count();
        let pad = " ".repeat(width.saturating_sub(len));
        if i == 1 {
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

/// `YYYY-MM-DD HH:MM:SS UTC`, without any date/time dependency.
pub fn format_utc(t: SystemTime) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian calendar
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1); // [1, 31]
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1); // [1, 12]
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::RttSummary;
    use std::time::Duration;

    fn at(secs: i64) -> SystemTime {
        if secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(secs.unsigned_abs())
        } else {
            UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
        }
    }

    #[test]
    fn utc_known_instants() {
        assert_eq!(format_utc(at(0)), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(at(-1)), "1969-12-31 23:59:59 UTC");
        assert_eq!(format_utc(at(951_782_400)), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(at(1_234_567_890)), "2009-02-13 23:31:30 UTC");
        assert_eq!(format_utc(at(1_582_934_400)), "2020-02-29 00:00:00 UTC");
        assert_eq!(format_utc(at(1_700_000_000)), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_utc(at(4_102_444_800)), "2100-01-01 00:00:00 UTC");
        // 2100 is not a leap year: Mar 1 follows Feb 28.
        assert_eq!(format_utc(at(4_107_542_400)), "2100-03-01 00:00:00 UTC");
        assert_eq!(format_utc(at(4_107_456_000)), "2100-02-28 00:00:00 UTC");
    }

    fn rtt(last: f64, avg: f64, best: f64, worst: f64, sd: f64, jit: f64) -> Option<RttSummary> {
        Some(RttSummary {
            count: 5,
            last_ms: last,
            min_ms: best,
            avg_ms: avg,
            max_ms: worst,
            stddev_ms: sd,
            jitter_ms: jit,
        })
    }

    fn snapshot() -> MtrSnapshot {
        MtrSnapshot {
            target: "203.0.113.9".parse().unwrap(),
            cycle: 10,
            total_cycles: 10,
            hops: vec![
                HopSnapshot {
                    ttl: 1,
                    addr: Some("192.168.1.1".parse().unwrap()),
                    other_addrs: vec![],
                    name: Some("gw.lan".into()),
                    sent: 10,
                    received: 10,
                    loss_percent: 0.0,
                    rtt: rtt(0.9, 1.0, 0.8, 1.4, 0.2, 0.16),
                    address_changes: 0,
                },
                HopSnapshot {
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
                HopSnapshot {
                    ttl: 3,
                    addr: Some("10.9.9.9".parse().unwrap()),
                    other_addrs: vec!["10.0.0.2".parse().unwrap()],
                    name: None,
                    sent: 10,
                    received: 9,
                    loss_percent: 10.0,
                    rtt: rtt(12.34, 12.5, 11.0, 20.26, 2.0, 3.0),
                    address_changes: 4,
                },
                HopSnapshot {
                    ttl: 4,
                    addr: Some("203.0.113.9".parse().unwrap()),
                    other_addrs: vec![],
                    name: Some("node.example.com".into()),
                    sent: 10,
                    received: 10,
                    loss_percent: 0.0,
                    rtt: rtt(30.0, 31.0, 29.5, 40.0, 3.1, 2.2),
                    address_changes: 0,
                },
            ],
            destination_reached: true,
            cancelled: false,
        }
    }

    #[test]
    fn golden_report() {
        let ctx = ReportContext {
            source_public_ip: Some("198.51.100.7".parse().unwrap()),
            generated_at: at(1_700_000_000),
            target: "node.example.com".into(),
        };
        let expected = "\
PacketWard MTR report
Target: node.example.com (203.0.113.9)
Generated: 2023-11-14 22:13:20 UTC
Source public IP: 198.51.100.7
Cycles: 10 of 10
Result: destination reached

Hop  Host                            Loss%  Sent  Last   Avg  Best  Wrst  StDev  Jitter
  1  gw.lan (192.168.1.1)              0.0    10   0.9   1.0   0.8   1.4    0.2     0.2
  2  ???                             100.0    10     -     -     -     -      -       -
  3  10.9.9.9                         10.0    10  12.3  12.5  11.0  20.3    2.0     3.0
     +- 10.0.0.2
  4  node.example.com (203.0.113.9)    0.0    10  30.0  31.0  29.5  40.0    3.1     2.2
";
        assert_eq!(format_report(&snapshot(), &ctx), expected);
    }

    #[test]
    fn source_ip_line_is_omitted_when_unknown() {
        let ctx = ReportContext {
            source_public_ip: None,
            generated_at: at(0),
            target: "203.0.113.9".into(),
        };
        let text = format_report(&snapshot(), &ctx);
        assert!(!text.contains("Source public IP"));
        assert!(text.contains("Target: 203.0.113.9\n"), "{text}");
    }

    #[test]
    fn output_is_deterministic_and_has_no_trailing_spaces() {
        let ctx = ReportContext {
            source_public_ip: None,
            generated_at: at(5),
            target: String::new(),
        };
        let a = format_report(&snapshot(), &ctx);
        assert_eq!(a, format_report(&snapshot(), &ctx));
        assert!(a.lines().all(|l| l == l.trim_end()));
    }

    #[test]
    fn partial_run_and_unreached_destination_are_labelled() {
        let mut s = snapshot();
        s.cycle = 3;
        s.destination_reached = false;
        let ctx = ReportContext {
            source_public_ip: None,
            generated_at: at(0),
            target: "x".into(),
        };
        let text = format_report(&s, &ctx);
        assert!(text.contains("Cycles: 3 of 10\n"));
        assert!(text.contains("Result: destination not reached\n"));
    }
}
