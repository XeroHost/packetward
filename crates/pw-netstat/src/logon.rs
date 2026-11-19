// SPDX-License-Identifier: GPL-3.0-or-later
//! Successful RDP logons learned from the Windows event log, and the set of addresses they build.
//!
//! Pure and platform-agnostic: the Win32 side only hands over rendered event XML. Two events count:
//!
//! * **Security 4624** with `LogonType` 10 (RemoteInteractive, a new session) or 7 (an RDP
//!   reconnect; a console unlock has no remote address and is ignored): `IpAddress` is the client;
//! * **TerminalServices-RemoteConnectionManager 1149** ("user authentication succeeded"): `Param3`
//!   is the client address.
//!
//! Failed logons (4625) and mere connections never enter the set: a brute-force bot must not be
//! able to earn protection, and a legitimate user who mistypes the password on reconnect is still
//! protected because of an earlier successful logon within the window.

use std::collections::HashMap;
use std::net::IpAddr;

use pw_proto::TrustedAddress;

/// One successful RDP logon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogonEvent {
    pub addr: IpAddr,
    pub at_unix_ms: u64,
}

/// Longest time an event may claim to be in the future before it is clamped (clock skew).
const FUTURE_SLACK_MS: u64 = 5 * 60 * 1000;

/// Text between `open` and the next `<`, for the first occurrence of `open` in `xml`.
fn text_after<'a>(xml: &'a str, open: &str) -> Option<&'a str> {
    let start = xml.find(open)? + open.len();
    let rest = &xml[start..];
    Some(rest[..rest.find('<')?].trim())
}

/// Text of the first `<tag ...>text</tag>`, attributes allowed (`<EventID Qualifiers='0'>1149</EventID>`).
fn element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{tag}"))?;
    let gt = xml[open..].find('>')? + open + 1;
    let rest = &xml[gt..];
    Some(rest[..rest.find('<')?].trim())
}

/// Value of `<Data Name='name'>value</Data>` (either quote style).
fn data_named<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    for quote in ['\'', '"'] {
        let marker = format!("Name={quote}{name}{quote}");
        if let Some(at) = xml.find(&marker) {
            let rest = &xml[at + marker.len()..];
            let gt = rest.find('>')?;
            let body = &rest[gt + 1..];
            return Some(body[..body.find('<')?].trim());
        }
    }
    None
}

/// The value of an XML attribute inside the first tag that starts with `<tag`.
fn attribute<'a>(xml: &'a str, tag: &str, attr: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{tag}"))?;
    let end = xml[open..].find('>')? + open;
    let element = &xml[open..end];
    for quote in ['\'', '"'] {
        let marker = format!("{attr}={quote}");
        if let Some(at) = element.find(&marker) {
            let value = &element[at + marker.len()..];
            return Some(&value[..value.find(quote)?]);
        }
    }
    None
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian), Howard Hinnant's algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-19T04:31:22.123456700Z` to Unix milliseconds.
pub fn parse_system_time(text: &str) -> Option<u64> {
    let (date, time) = text.trim().strip_suffix('Z')?.split_once('T')?;
    let mut d = date.split('-');
    let (year, month, day) = (
        d.next()?.parse::<i64>().ok()?,
        d.next()?.parse::<i64>().ok()?,
        d.next()?.parse::<i64>().ok()?,
    );
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut t = clock.split(':');
    let (hour, minute, second) = (
        t.next()?.parse::<i64>().ok()?,
        t.next()?.parse::<i64>().ok()?,
        t.next()?.parse::<i64>().ok()?,
    );
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let millis: i64 = format!("{fraction:0<3}")[..3].parse().ok()?;
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(seconds * 1000 + millis).ok()
}

/// A usable remote address: parsed, folded to IPv4 when mapped, never loopback or unspecified.
fn client_address(text: &str) -> Option<IpAddr> {
    let text = text.split('%').next()?.trim(); // drop an IPv6 scope id
    let addr = text.parse::<IpAddr>().ok()?.to_canonical();
    (!addr.is_loopback() && !addr.is_unspecified()).then_some(addr)
}

/// Extracts a successful RDP logon from a rendered event, or `None` for anything else (other event
/// ids, other logon types, missing or local addresses, malformed XML).
pub fn parse_logon_event(xml: &str) -> Option<LogonEvent> {
    let id = element_text(xml, "EventID")?.parse::<u32>().ok()?;
    let at_unix_ms = parse_system_time(attribute(xml, "TimeCreated", "SystemTime")?)?;
    let address = match id {
        4624 => {
            // 10 = new RDP session, 7 = RDP reconnect. Type 7 is also a local unlock, which has no
            // remote address and is dropped by `client_address`.
            if !matches!(data_named(xml, "LogonType")?, "10" | "7") {
                return None;
            }
            data_named(xml, "IpAddress")?
        }
        1149 => text_after(xml, "<Param3>")?,
        _ => return None,
    };
    Some(LogonEvent {
        addr: client_address(address)?,
        at_unix_ms,
    })
}

/// Extracts a **failed** logon from a remote address (Security 4625), the input of RDP brute-force
/// detection. RDP with Network Level Authentication logs these as LogonType 3 (network), without NLA
/// as 10 (remote interactive); 7 is a failed reconnect. Failures without a remote address (a local
/// console, service accounts logging on from the machine itself) are dropped.
///
/// These events never enter the trust set: a bot that fails logons must not earn protection.
pub fn parse_failed_logon_event(xml: &str) -> Option<LogonEvent> {
    let id = element_text(xml, "EventID")?.parse::<u32>().ok()?;
    if id != 4625 {
        return None;
    }
    if !matches!(data_named(xml, "LogonType")?, "3" | "7" | "10") {
        return None;
    }
    Some(LogonEvent {
        addr: client_address(data_named(xml, "IpAddress")?)?,
        at_unix_ms: parse_system_time(attribute(xml, "TimeCreated", "SystemTime")?)?,
    })
}

/// Addresses with a successful RDP logon inside a sliding window. Bounded: when more than `cap`
/// distinct addresses appear, the least recently seen ones are dropped.
#[derive(Debug)]
pub struct TrustSet {
    window_ms: u64,
    cap: usize,
    last: HashMap<IpAddr, u64>,
}

impl TrustSet {
    pub fn new(window_days: u32, cap: usize) -> Self {
        Self {
            window_ms: u64::from(window_days) * 24 * 60 * 60 * 1000,
            cap: cap.max(1),
            last: HashMap::new(),
        }
    }

    pub fn window_days(&self) -> u32 {
        u32::try_from(self.window_ms / (24 * 60 * 60 * 1000)).unwrap_or(u32::MAX)
    }

    /// Records a logon, keeping the most recent time per address.
    pub fn record(&mut self, event: LogonEvent, now_unix_ms: u64) {
        let at = event
            .at_unix_ms
            .min(now_unix_ms.saturating_add(FUTURE_SLACK_MS));
        if now_unix_ms.saturating_sub(at) > self.window_ms {
            return; // already outside the window
        }
        let entry = self.last.entry(event.addr).or_insert(0);
        *entry = (*entry).max(at);
        if self.last.len() > self.cap {
            if let Some(oldest) = self.last.iter().min_by_key(|(_, at)| **at).map(|(a, _)| *a) {
                self.last.remove(&oldest);
            }
        }
    }

    /// The trusted addresses at `now`, most recent logon first. Expired entries are dropped.
    pub fn addresses(&mut self, now_unix_ms: u64) -> Vec<TrustedAddress> {
        let window = self.window_ms;
        self.last
            .retain(|_, at| now_unix_ms.saturating_sub(*at) <= window);
        let mut list: Vec<(IpAddr, u64)> = self.last.iter().map(|(a, t)| (*a, *t)).collect();
        list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        list.into_iter()
            .map(|(addr, last_logon_unix_ms)| TrustedAddress {
                addr: addr.to_string(),
                last_logon_unix_ms,
            })
            .collect()
    }

    pub fn contains(&self, addr: IpAddr, now_unix_ms: u64) -> bool {
        self.last
            .get(&addr.to_canonical())
            .is_some_and(|at| now_unix_ms.saturating_sub(*at) <= self.window_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60 * 1000;

    fn xml_4624(logon_type: &str, ip: &str) -> String {
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID>\
             <TimeCreated SystemTime='2026-11-19T04:31:22.123456700Z'/></System><EventData>\
             <Data Name='TargetUserName'>Administrator</Data><Data Name='LogonType'>{logon_type}</Data>\
             <Data Name='IpAddress'>{ip}</Data><Data Name='IpPort'>51234</Data></EventData></Event>"
        )
    }

    fn xml_1149(ip: &str) -> String {
        format!(
            "<Event><System><EventID Qualifiers='0'>1149</EventID>\
             <TimeCreated SystemTime=\"2026-11-19T04:31:22.0000000Z\"/></System><UserData>\
             <EventXML xmlns='Event_NS'><Param1>Administrator</Param1><Param2></Param2>\
             <Param3>{ip}</Param3></EventXML></UserData></Event>"
        )
    }

    #[test]
    fn a_type_10_logon_gives_its_address_and_time() {
        let event = parse_logon_event(&xml_4624("10", "143.20.99.200")).unwrap();
        assert_eq!(event.addr, "143.20.99.200".parse::<IpAddr>().unwrap());
        assert_eq!(event.at_unix_ms % 1000, 123);
        assert_eq!(
            event.at_unix_ms,
            parse_system_time("2026-11-19T04:31:22.123Z").unwrap()
        );
    }

    #[test]
    fn other_logon_types_do_not_count() {
        for logon_type in ["2", "3", "4", "5", "8", "11"] {
            assert_eq!(
                parse_logon_event(&xml_4624(logon_type, "143.20.99.200")),
                None,
                "{logon_type}"
            );
        }
    }

    #[test]
    fn an_rdp_reconnect_is_type_7_and_counts_only_with_a_remote_address() {
        let reconnect = parse_logon_event(&xml_4624("7", "143.20.99.200")).unwrap();
        assert_eq!(reconnect.addr, "143.20.99.200".parse::<IpAddr>().unwrap());
        // A console unlock is also type 7 but has no remote address.
        assert_eq!(parse_logon_event(&xml_4624("7", "-")), None);
        assert_eq!(parse_logon_event(&xml_4624("7", "::1")), None);
    }

    #[test]
    fn missing_and_local_addresses_are_ignored() {
        for ip in ["-", "", "::1", "127.0.0.1", "0.0.0.0", "::", "not an ip"] {
            assert_eq!(parse_logon_event(&xml_4624("10", ip)), None, "{ip:?}");
        }
    }

    #[test]
    fn event_1149_uses_param3_and_the_qualifiers_attribute_is_fine() {
        let event = parse_logon_event(&xml_1149("203.0.113.7")).unwrap();
        assert_eq!(event.addr, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ipv6_with_scope_and_mapped_addresses_are_normalized() {
        let event = parse_logon_event(&xml_4624("10", "2001:db8::5%12")).unwrap();
        assert_eq!(event.addr, "2001:db8::5".parse::<IpAddr>().unwrap());
        let event = parse_logon_event(&xml_4624("10", "::ffff:203.0.113.9")).unwrap();
        assert_eq!(event.addr, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn failed_rdp_logons_give_the_attacker_address_for_nla_and_non_nla() {
        let nla = xml_4624("3", "198.51.100.9").replace("4624", "4625");
        let event = parse_failed_logon_event(&nla).unwrap();
        assert_eq!(event.addr, "198.51.100.9".parse::<IpAddr>().unwrap());
        assert!(event.at_unix_ms > 0);
        let classic = xml_4624("10", "2001:db8::7").replace("4624", "4625");
        assert!(parse_failed_logon_event(&classic).is_some());
    }

    #[test]
    fn failed_logon_parser_ignores_everything_else() {
        let bad_type = xml_4624("2", "198.51.100.9").replace("4624", "4625"); // interactive console
        assert_eq!(parse_failed_logon_event(&bad_type), None);
        for ip in ["-", "", "127.0.0.1", "::1", "0.0.0.0"] {
            let local = xml_4624("3", ip).replace("4624", "4625");
            assert_eq!(parse_failed_logon_event(&local), None, "{ip:?}");
        }
        // A success is not a failure, and failures never parse as successes.
        assert_eq!(
            parse_failed_logon_event(&xml_4624("10", "198.51.100.9")),
            None
        );
        let failed = xml_4624("10", "198.51.100.9").replace("4624", "4625");
        assert_eq!(parse_logon_event(&failed), None);
        assert_eq!(parse_failed_logon_event(""), None);
    }

    #[test]
    fn failed_logons_and_unrelated_events_never_count() {
        let failed = xml_4624("10", "198.51.100.1").replace("4624", "4625");
        assert_eq!(parse_logon_event(&failed), None);
        assert_eq!(
            parse_logon_event("<Event><System><EventID>4688</EventID></System></Event>"),
            None
        );
        assert_eq!(parse_logon_event("not xml at all"), None);
        assert_eq!(parse_logon_event(""), None);
        let no_time = xml_4624("10", "1.2.3.4").replace("TimeCreated", "Other");
        assert_eq!(parse_logon_event(&no_time), None);
    }

    #[test]
    fn system_time_parses_known_instants() {
        assert_eq!(parse_system_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_system_time("2000-03-01T00:00:00.000Z"),
            Some(951_868_800_000)
        );
        // Leap day, with a fractional second of 100 ns ticks.
        assert_eq!(
            parse_system_time("2024-02-29T12:00:00.5000000Z"),
            Some(1_709_208_000_500)
        );
        assert_eq!(parse_system_time("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_system_time("garbage"), None);
        assert_eq!(parse_system_time("2026-11-19T04:31:22"), None); // not UTC
    }

    fn event(ip: &str, at: u64) -> LogonEvent {
        LogonEvent {
            addr: ip.parse().unwrap(),
            at_unix_ms: at,
        }
    }

    #[test]
    fn the_set_keeps_the_latest_logon_per_address_and_sorts_recent_first() {
        let now = 100 * DAY;
        let mut set = TrustSet::new(30, 100);
        set.record(event("1.1.1.1", now - 10 * DAY), now);
        set.record(event("2.2.2.2", now - DAY), now);
        set.record(event("1.1.1.1", now - 2 * DAY), now); // newer for the same address
        set.record(event("1.1.1.1", now - 20 * DAY), now); // older: must not move it back
        let list = set.addresses(now);
        let order: Vec<(&str, u64)> = list
            .iter()
            .map(|a| (a.addr.as_str(), a.last_logon_unix_ms))
            .collect();
        assert_eq!(order, [("2.2.2.2", now - DAY), ("1.1.1.1", now - 2 * DAY)]);
    }

    #[test]
    fn logons_outside_the_window_are_dropped_and_expire() {
        let now = 100 * DAY;
        let mut set = TrustSet::new(30, 100);
        set.record(event("3.3.3.3", now - 31 * DAY), now); // too old on arrival
        assert!(set.addresses(now).is_empty());
        set.record(event("4.4.4.4", now - 29 * DAY), now);
        assert_eq!(set.addresses(now).len(), 1);
        assert!(set.contains("4.4.4.4".parse().unwrap(), now));
        // Two days later it has aged out.
        assert!(set.addresses(now + 2 * DAY).is_empty());
        assert!(!set.contains("4.4.4.4".parse().unwrap(), now + 2 * DAY));
    }

    #[test]
    fn the_window_is_configurable() {
        let now = 100 * DAY;
        let mut set = TrustSet::new(7, 100);
        assert_eq!(set.window_days(), 7);
        set.record(event("5.5.5.5", now - 8 * DAY), now);
        assert!(set.addresses(now).is_empty());
        set.record(event("5.5.5.5", now - 6 * DAY), now);
        assert_eq!(set.addresses(now).len(), 1);
    }

    #[test]
    fn the_set_is_bounded_and_drops_the_least_recent_address() {
        let now = 100 * DAY;
        let mut set = TrustSet::new(30, 3);
        for i in 0..6u64 {
            set.record(
                event(&format!("10.0.0.{}", i + 1), now - (10 - i) * 1000),
                now,
            );
        }
        let list = set.addresses(now);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].addr, "10.0.0.6"); // the three most recent survive
    }

    #[test]
    fn a_future_timestamp_is_clamped_instead_of_trusted_forever() {
        let now = 100 * DAY;
        let mut set = TrustSet::new(30, 10);
        set.record(event("6.6.6.6", now + 400 * DAY), now); // absurd clock
        let list = set.addresses(now);
        assert_eq!(list.len(), 1);
        assert!(list[0].last_logon_unix_ms <= now + FUTURE_SLACK_MS);
    }

    #[test]
    fn mapped_ipv6_matches_its_ipv4_form() {
        let now = 100 * DAY;
        let mut set = TrustSet::new(30, 10);
        set.record(event("203.0.113.9", now), now);
        assert!(set.contains("::ffff:203.0.113.9".parse().unwrap(), now));
    }
}
