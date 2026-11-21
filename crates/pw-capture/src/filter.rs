// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! A small packet filter language, evaluated in Rust on decoded [`PacketMeta`] and, when it can be
//! expressed exactly, mapped to a BPF string for the Npcap backend.
//!
//! ```text
//! expr    := and ("or" and)*
//! and     := not ("and" not)*
//! not     := "not" not | "(" expr ")" | primary
//! primary := "any"
//!          | "tcp" | "udp" | "icmp"                 (icmp also matches ICMPv6)
//!          | "proto" NUMBER                          (IP protocol / next-header number, 0-255)
//!          | "inbound" | "outbound"                  (relative to this machine)
//!          | ["src" | "dst"] ("host" | "net") ADDR[/PREFIX]
//!          | ["src" | "dst"] ("port" | "portrange") PORT[-PORT]    (TCP and UDP only)
//! ```
//!
//! Keywords are case-insensitive. Examples: `tcp and dst port 3389`, `udp and not host 10.0.0.0/8`,
//! `inbound and (port 53 or port 123)`.
//!
//! Rust evaluation is authoritative. [`Filter::to_bpf`] returns `None` whenever the BPF form could differ
//! from it (any `not`, or a direction test), and the backend then captures everything and the pipeline
//! filters. Where a BPF string exists it can only differ for IPv6 packets with extension headers
//! (classic BPF does not walk them), in which case the kernel filter captures *less*, never more.

use std::str::FromStr;

use pw_core::{Cidr, Direction, PacketMeta, Protocol};

const MAX_SOURCE_LEN: usize = 1024;
const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("filter is too long (more than {MAX_SOURCE_LEN} characters)")]
    TooLong,
    #[error("filter is nested too deeply")]
    TooDeep,
    #[error("unexpected end of filter")]
    UnexpectedEnd,
    #[error("unexpected {0:?} in filter")]
    Unexpected(String),
    #[error("invalid address or network {0:?}")]
    BadAddress(String),
    #[error("invalid port or port range {0:?}")]
    BadPort(String),
    #[error("invalid protocol number {0:?}")]
    BadProto(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Any,
    Src,
    Dst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoTest {
    Tcp,
    Udp,
    Icmp,
    Number(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Any,
    Proto(ProtoTest),
    Direction(Direction),
    Host(Side, Cidr),
    Port(Side, u16, u16),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

/// A parsed filter. Cheap to clone; evaluating it never allocates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    source: String,
    expr: Expr,
}

impl Filter {
    /// Parses a filter expression. An empty or blank text is `any`.
    pub fn parse(text: &str) -> Result<Self, FilterError> {
        if text.len() > MAX_SOURCE_LEN {
            return Err(FilterError::TooLong);
        }
        let tokens = tokenize(text);
        let expr = if tokens.is_empty() {
            Expr::Any
        } else {
            let mut parser = Parser {
                tokens: &tokens,
                pos: 0,
            };
            let expr = parser.or_expr(0)?;
            if let Some(extra) = parser.tokens.get(parser.pos) {
                return Err(FilterError::Unexpected((*extra).to_owned()));
            }
            expr
        };
        Ok(Self {
            source: text.trim().to_owned(),
            expr,
        })
    }

    /// A filter that matches every packet.
    pub fn any() -> Self {
        Self {
            source: "any".to_owned(),
            expr: Expr::Any,
        }
    }

    /// The text this filter was parsed from.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn is_any(&self) -> bool {
        matches!(self.expr, Expr::Any)
    }

    /// Does this packet pass?
    pub fn matches(&self, meta: &PacketMeta) -> bool {
        eval(&self.expr, meta)
    }

    /// The same filter as a BPF string, or `None` when it cannot be expressed exactly (see the module docs).
    pub fn to_bpf(&self) -> Option<String> {
        if self.is_any() || !bpf_safe(&self.expr) {
            return None;
        }
        Some(bpf(&self.expr))
    }
}

impl FromStr for Filter {
    type Err = FilterError;

    fn from_str(text: &str) -> Result<Self, FilterError> {
        Self::parse(text)
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

fn proto_matches(test: ProtoTest, proto: Protocol) -> bool {
    match (test, proto) {
        (ProtoTest::Tcp, Protocol::Tcp)
        | (ProtoTest::Udp, Protocol::Udp)
        | (ProtoTest::Icmp, Protocol::Icmp) => true,
        (ProtoTest::Number(n), Protocol::Tcp) => n == 6,
        (ProtoTest::Number(n), Protocol::Udp) => n == 17,
        // ICMP (1) and ICMPv6 (58) share a variant; either number matches it.
        (ProtoTest::Number(n), Protocol::Icmp) => n == 1 || n == 58,
        (ProtoTest::Number(n), Protocol::Other(o)) => n == o,
        _ => false,
    }
}

fn eval(expr: &Expr, m: &PacketMeta) -> bool {
    match expr {
        Expr::Any => true,
        Expr::Proto(test) => proto_matches(*test, m.proto),
        Expr::Direction(d) => m.direction == *d,
        Expr::Host(side, net) => match side {
            Side::Any => net.contains(m.src) || net.contains(m.dst),
            Side::Src => net.contains(m.src),
            Side::Dst => net.contains(m.dst),
        },
        Expr::Port(side, lo, hi) => {
            if !matches!(m.proto, Protocol::Tcp | Protocol::Udp) {
                return false;
            }
            let hit = |p: u16| p >= *lo && p <= *hi;
            match side {
                Side::Any => hit(m.src_port) || hit(m.dst_port),
                Side::Src => hit(m.src_port),
                Side::Dst => hit(m.dst_port),
            }
        }
        Expr::Not(inner) => !eval(inner, m),
        Expr::And(items) => items.iter().all(|e| eval(e, m)),
        Expr::Or(items) => items.iter().any(|e| eval(e, m)),
    }
}

// ---------------------------------------------------------------------------------------------
// BPF
// ---------------------------------------------------------------------------------------------

fn bpf_safe(expr: &Expr) -> bool {
    match expr {
        Expr::Direction(_) | Expr::Not(_) => false,
        Expr::And(items) | Expr::Or(items) => items.iter().all(bpf_safe),
        _ => true,
    }
}

fn side_word(side: Side) -> &'static str {
    match side {
        Side::Any => "",
        Side::Src => "src ",
        Side::Dst => "dst ",
    }
}

/// Only called for expressions that passed [`bpf_safe`]. Built from the typed tree, never from user text.
fn bpf(expr: &Expr) -> String {
    match expr {
        Expr::Any => "(ip or ip6)".to_owned(),
        Expr::Proto(ProtoTest::Tcp) => "tcp".to_owned(),
        Expr::Proto(ProtoTest::Udp) => "udp".to_owned(),
        Expr::Proto(ProtoTest::Icmp) => "(icmp or icmp6)".to_owned(),
        Expr::Proto(ProtoTest::Number(n)) => format!("(ip proto {n} or ip6 proto {n})"),
        // Unreachable through `to_bpf`; harmless fallback that matches everything.
        Expr::Direction(_) | Expr::Not(_) => "(ip or ip6)".to_owned(),
        Expr::Host(side, net) => {
            let side = side_word(*side);
            let host_bits = if net.network().is_ipv4() { 32 } else { 128 };
            if net.prefix() == 0 {
                if net.network().is_ipv4() {
                    "ip".to_owned()
                } else {
                    "ip6".to_owned()
                }
            } else if net.prefix() == host_bits {
                format!("({side}host {})", net.network())
            } else {
                format!("({side}net {}/{})", net.network(), net.prefix())
            }
        }
        Expr::Port(side, lo, hi) => {
            let side = side_word(*side);
            if lo == hi {
                format!("((tcp or udp) and {side}port {lo})")
            } else {
                format!("((tcp or udp) and {side}portrange {lo}-{hi})")
            }
        }
        Expr::And(items) => join(items, " and "),
        Expr::Or(items) => join(items, " or "),
    }
}

fn join(items: &[Expr], sep: &str) -> String {
    let parts: Vec<String> = items.iter().map(bpf).collect();
    format!("({})", parts.join(sep))
}

// ---------------------------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------------------------

fn tokenize(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        let split = c.is_whitespace() || c == '(' || c == ')';
        if split {
            if let Some(s) = start.take() {
                tokens.push(&text[s..i]);
            }
            if c == '(' || c == ')' {
                tokens.push(&text[i..i + 1]);
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        tokens.push(&text[s..]);
    }
    tokens
}

struct Parser<'a> {
    tokens: &'a [&'a str],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).copied()
    }

    fn peek_is(&self, word: &str) -> bool {
        self.peek().is_some_and(|t| t.eq_ignore_ascii_case(word))
    }

    fn next(&mut self) -> Result<&str, FilterError> {
        let token = self
            .tokens
            .get(self.pos)
            .copied()
            .ok_or(FilterError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(token)
    }

    fn or_expr(&mut self, depth: usize) -> Result<Expr, FilterError> {
        if depth > MAX_DEPTH {
            return Err(FilterError::TooDeep);
        }
        let mut items = vec![self.and_expr(depth)?];
        while self.peek_is("or") {
            self.pos += 1;
            items.push(self.and_expr(depth)?);
        }
        Ok(if items.len() == 1 {
            items.swap_remove(0)
        } else {
            Expr::Or(items)
        })
    }

    fn and_expr(&mut self, depth: usize) -> Result<Expr, FilterError> {
        let mut items = vec![self.not_expr(depth)?];
        while self.peek_is("and") {
            self.pos += 1;
            items.push(self.not_expr(depth)?);
        }
        Ok(if items.len() == 1 {
            items.swap_remove(0)
        } else {
            Expr::And(items)
        })
    }

    fn not_expr(&mut self, depth: usize) -> Result<Expr, FilterError> {
        if depth > MAX_DEPTH {
            return Err(FilterError::TooDeep);
        }
        if self.peek_is("not") {
            self.pos += 1;
            return Ok(Expr::Not(Box::new(self.not_expr(depth + 1)?)));
        }
        if self.peek() == Some("(") {
            self.pos += 1;
            let inner = self.or_expr(depth + 1)?;
            return match self.next()? {
                ")" => Ok(inner),
                other => Err(FilterError::Unexpected(other.to_owned())),
            };
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, FilterError> {
        let word = self.next()?.to_ascii_lowercase();
        match word.as_str() {
            "any" => Ok(Expr::Any),
            "tcp" => Ok(Expr::Proto(ProtoTest::Tcp)),
            "udp" => Ok(Expr::Proto(ProtoTest::Udp)),
            "icmp" | "icmp6" | "icmpv6" => Ok(Expr::Proto(ProtoTest::Icmp)),
            "proto" => {
                let value = self.next()?;
                let number = value
                    .parse::<u8>()
                    .map_err(|_| FilterError::BadProto(value.to_owned()))?;
                Ok(Expr::Proto(ProtoTest::Number(number)))
            }
            "inbound" | "in" => Ok(Expr::Direction(Direction::Inbound)),
            "outbound" | "out" => Ok(Expr::Direction(Direction::Outbound)),
            "src" => self.sided(Side::Src),
            "dst" => self.sided(Side::Dst),
            "host" | "net" | "port" | "portrange" => {
                self.pos -= 1;
                self.sided(Side::Any)
            }
            other => Err(FilterError::Unexpected(other.to_owned())),
        }
    }

    fn sided(&mut self, side: Side) -> Result<Expr, FilterError> {
        let word = self.next()?.to_ascii_lowercase();
        match word.as_str() {
            "host" | "net" => {
                let value = self.next()?;
                let net = value
                    .parse::<Cidr>()
                    .map_err(|_| FilterError::BadAddress(value.to_owned()))?;
                Ok(Expr::Host(side, net))
            }
            "port" | "portrange" => {
                let value = self.next()?;
                let (lo, hi) = parse_ports(value)?;
                Ok(Expr::Port(side, lo, hi))
            }
            other => Err(FilterError::Unexpected(other.to_owned())),
        }
    }
}

fn parse_ports(text: &str) -> Result<(u16, u16), FilterError> {
    let bad = || FilterError::BadPort(text.to_owned());
    let (lo, hi) = match text.split_once('-') {
        Some((lo, hi)) => (
            lo.parse::<u16>().map_err(|_| bad())?,
            hi.parse::<u16>().map_err(|_| bad())?,
        ),
        None => {
            let port = text.parse::<u16>().map_err(|_| bad())?;
            (port, port)
        }
    };
    if lo > hi {
        return Err(bad());
    }
    Ok((lo, hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(
        proto: Protocol,
        src: &str,
        sport: u16,
        dst: &str,
        dport: u16,
        dir: Direction,
    ) -> PacketMeta {
        PacketMeta {
            timestamp_ns: 0,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            src_port: sport,
            dst_port: dport,
            proto,
            tcp_flags: 0,
            len: 100,
            direction: dir,
        }
    }

    fn rdp() -> PacketMeta {
        meta(
            Protocol::Tcp,
            "203.0.113.9",
            50000,
            "10.0.0.5",
            3389,
            Direction::Inbound,
        )
    }

    fn dns_out() -> PacketMeta {
        meta(
            Protocol::Udp,
            "10.0.0.5",
            40000,
            "1.1.1.1",
            53,
            Direction::Outbound,
        )
    }

    fn ping() -> PacketMeta {
        meta(
            Protocol::Icmp,
            "198.51.100.1",
            0,
            "10.0.0.5",
            0,
            Direction::Inbound,
        )
    }

    fn check(text: &str, expect: [bool; 3]) {
        let f = Filter::parse(text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        assert_eq!(
            [f.matches(&rdp()), f.matches(&dns_out()), f.matches(&ping())],
            expect,
            "{text:?}"
        );
    }

    #[test]
    fn evaluates_primitives() {
        check("", [true, true, true]);
        check("any", [true, true, true]);
        check("tcp", [true, false, false]);
        check("UDP", [false, true, false]);
        check("icmp", [false, false, true]);
        check("proto 6", [true, false, false]);
        check("proto 1", [false, false, true]);
        check("inbound", [true, false, true]);
        check("outbound", [false, true, false]);
        check("port 3389", [true, false, false]);
        check("dst port 3389", [true, false, false]);
        check("src port 3389", [false, false, false]);
        check("port 50000-50010", [true, false, false]);
        check("portrange 40000-40001", [false, true, false]);
        check("host 203.0.113.9", [true, false, false]);
        check("src host 203.0.113.0/24", [true, false, false]);
        check("dst net 10.0.0.0/8", [true, false, true]);
        check("host 10.0.0.5", [true, true, true]);
    }

    #[test]
    fn evaluates_combinations() {
        check("tcp and dst port 3389", [true, false, false]);
        check("tcp or udp", [true, true, false]);
        check("not tcp", [false, true, true]);
        check("not (tcp or udp)", [false, false, true]);
        check("inbound and (port 53 or port 3389)", [true, false, false]);
        check("udp and not host 10.0.0.0/8", [false, false, false]);
        check("tcp and udp", [false, false, false]);
        // `and` binds tighter than `or`.
        check("icmp or tcp and port 1", [false, false, true]);
    }

    #[test]
    fn ports_only_apply_to_tcp_and_udp() {
        let mut other = ping();
        other.proto = Protocol::Other(47);
        let f = Filter::parse("port 0").unwrap();
        assert!(!f.matches(&other));
        assert!(!f.matches(&ping()));
    }

    #[test]
    fn matches_ipv6_and_mapped_addresses() {
        let m = meta(
            Protocol::Udp,
            "2001:db8::1",
            1000,
            "2001:db8:1::2",
            53,
            Direction::Inbound,
        );
        assert!(Filter::parse("host 2001:db8::/32").unwrap().matches(&m));
        assert!(!Filter::parse("host 2001:db9::/32").unwrap().matches(&m));
        assert!(!Filter::parse("host 10.0.0.0/8").unwrap().matches(&m));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "tcp and",
            "port",
            "port 99999",
            "port 20-10",
            "host nonsense",
            "host 10.0.0.0/33",
            "proto 300",
            "(tcp",
            "tcp)",
            "tcp udp",
            "frobnicate",
            "src tcp",
            "not",
            "and tcp",
        ] {
            assert!(Filter::parse(bad).is_err(), "{bad:?} should not parse");
        }
        assert_eq!(Filter::parse(&"a".repeat(2000)), Err(FilterError::TooLong));
        let deep = format!("{}tcp{}", "(".repeat(40), ")".repeat(40));
        assert_eq!(Filter::parse(&deep), Err(FilterError::TooDeep));
        let nots = format!("{}tcp", "not ".repeat(40));
        assert_eq!(Filter::parse(&nots), Err(FilterError::TooDeep));
    }

    #[test]
    fn maps_to_bpf() {
        let bpf = |t: &str| Filter::parse(t).unwrap().to_bpf();
        assert_eq!(bpf("tcp").as_deref(), Some("tcp"));
        assert_eq!(bpf("icmp").as_deref(), Some("(icmp or icmp6)"));
        assert_eq!(
            bpf("tcp and dst port 3389").as_deref(),
            Some("(tcp and ((tcp or udp) and dst port 3389))")
        );
        assert_eq!(
            bpf("udp and port 10-20").as_deref(),
            Some("(udp and ((tcp or udp) and portrange 10-20))")
        );
        assert_eq!(
            bpf("src host 203.0.113.9").as_deref(),
            Some("(src host 203.0.113.9)")
        );
        assert_eq!(bpf("host 10.0.0.0/8").as_deref(), Some("(net 10.0.0.0/8)"));
        assert_eq!(
            bpf("dst net 2001:db8::/32").as_deref(),
            Some("(dst net 2001:db8::/32)")
        );
        assert_eq!(bpf("host 0.0.0.0/0").as_deref(), Some("ip"));
        assert_eq!(
            bpf("proto 47").as_deref(),
            Some("(ip proto 47 or ip6 proto 47)")
        );
        assert_eq!(bpf("tcp or udp").as_deref(), Some("(tcp or udp)"));
    }

    #[test]
    fn no_bpf_when_it_could_differ_from_rust() {
        for text in [
            "",
            "any",
            "inbound",
            "tcp and outbound",
            "not tcp",
            "udp or not port 53",
        ] {
            assert_eq!(Filter::parse(text).unwrap().to_bpf(), None, "{text:?}");
        }
    }
}
