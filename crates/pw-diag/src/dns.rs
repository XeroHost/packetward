// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS lookups: typed records, resolver choice, and the logic around a [`DnsBackend`]
//! (`ALL` aggregation, PTR from an IP, per-query timeout, error semantics).
//!
//! The wire work is done by [`HickoryBackend`](crate::HickoryBackend); this module has no
//! dependency on it, so everything here is tested against [`FakeDnsBackend`](crate::fake).
//!
//! # Result semantics
//!
//! * A name that exists but has no record of the requested type is **not** an error: the lookup
//!   succeeds with an empty record list.
//! * `NXDOMAIN` means the name does not exist at all.
//! * `ALL` never sends an `ANY` query (RFC 8482 resolvers answer it with junk). It queries every
//!   supported type concurrently and keeps the types that returned data. If **any** type says
//!   `NXDOMAIN` the whole lookup is `NXDOMAIN`. A type that times out or gets `SERVFAIL` is
//!   reported in [`DnsLookup::errors`] while the other types' records are still returned; only
//!   when nothing succeeded at all is the first such error returned as the failure.
//! * A literal IP address is looked up as a PTR record under `in-addr.arpa` / `ip6.arpa`; `ALL`
//!   on an IP means just that PTR query, and any other type on an IP is rejected.
//! * Names are queried as fully qualified: the resolver's search suffixes are never appended.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;
use tokio::time::Instant;

use crate::names::ReverseLookup;

/// Default per-query timeout.
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest per-query timeout accepted.
pub const MAX_DNS_TIMEOUT: Duration = Duration::from_secs(15);
/// Shortest per-query timeout accepted.
pub const MIN_DNS_TIMEOUT: Duration = Duration::from_millis(100);
/// Most servers in a custom resolver list.
pub const MAX_CUSTOM_SERVERS: usize = 4;

/// Record types the lookup supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Mail exchanger.
    Mx,
    /// Text.
    Txt,
    /// Name server.
    Ns,
    /// Start of authority.
    Soa,
    /// Canonical name.
    Cname,
    /// Reverse pointer.
    Ptr,
    /// Every type above (never a real `ANY` query).
    All,
}

impl DnsRecordType {
    /// Every concrete type, in the order `ALL` reports them.
    pub const CONCRETE: [DnsRecordType; 8] = [
        DnsRecordType::A,
        DnsRecordType::Aaaa,
        DnsRecordType::Mx,
        DnsRecordType::Txt,
        DnsRecordType::Ns,
        DnsRecordType::Soa,
        DnsRecordType::Cname,
        DnsRecordType::Ptr,
    ];

    /// The usual upper-case mnemonic.
    pub fn as_str(self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::Aaaa => "AAAA",
            DnsRecordType::Mx => "MX",
            DnsRecordType::Txt => "TXT",
            DnsRecordType::Ns => "NS",
            DnsRecordType::Soa => "SOA",
            DnsRecordType::Cname => "CNAME",
            DnsRecordType::Ptr => "PTR",
            DnsRecordType::All => "ALL",
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DnsRecordType {
    type Err = DnsFailure;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.trim().to_ascii_uppercase();
        DnsRecordType::CONCRETE
            .into_iter()
            .chain([DnsRecordType::All])
            .find(|t| t.as_str() == upper)
            .ok_or_else(|| DnsFailure::InvalidName(format!("unknown record type {s:?}")))
    }
}

/// The data of one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    /// A.
    A(Ipv4Addr),
    /// AAAA.
    Aaaa(Ipv6Addr),
    /// MX.
    Mx {
        /// Lower is preferred.
        preference: u16,
        /// Mail host (no trailing dot).
        exchange: String,
    },
    /// TXT, the character-strings of the record concatenated.
    Txt(String),
    /// NS (no trailing dot).
    Ns(String),
    /// SOA.
    Soa {
        /// Primary name server.
        mname: String,
        /// Responsible mailbox (dotted form).
        rname: String,
        /// Zone serial.
        serial: u32,
        /// Refresh interval, seconds.
        refresh: i32,
        /// Retry interval, seconds.
        retry: i32,
        /// Expire, seconds.
        expire: i32,
        /// Negative-caching TTL, seconds.
        minimum: u32,
    },
    /// CNAME target (no trailing dot).
    Cname(String),
    /// PTR target (no trailing dot).
    Ptr(String),
}

impl DnsRecordData {
    /// Which type this data belongs to.
    pub fn record_type(&self) -> DnsRecordType {
        match self {
            DnsRecordData::A(_) => DnsRecordType::A,
            DnsRecordData::Aaaa(_) => DnsRecordType::Aaaa,
            DnsRecordData::Mx { .. } => DnsRecordType::Mx,
            DnsRecordData::Txt(_) => DnsRecordType::Txt,
            DnsRecordData::Ns(_) => DnsRecordType::Ns,
            DnsRecordData::Soa { .. } => DnsRecordType::Soa,
            DnsRecordData::Cname(_) => DnsRecordType::Cname,
            DnsRecordData::Ptr(_) => DnsRecordType::Ptr,
        }
    }

    /// One-line human readable value, as `dig +short` would print it.
    pub fn value(&self) -> String {
        match self {
            DnsRecordData::A(ip) => ip.to_string(),
            DnsRecordData::Aaaa(ip) => ip.to_string(),
            DnsRecordData::Mx {
                preference,
                exchange,
            } => format!("{preference} {exchange}"),
            DnsRecordData::Txt(s)
            | DnsRecordData::Ns(s)
            | DnsRecordData::Cname(s)
            | DnsRecordData::Ptr(s) => s.clone(),
            DnsRecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
        }
    }
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Owner name (no trailing dot).
    pub name: String,
    /// Time to live in seconds.
    pub ttl: u32,
    /// The data.
    pub data: DnsRecordData,
}

impl DnsRecord {
    /// The record's type.
    pub fn record_type(&self) -> DnsRecordType {
        self.data.record_type()
    }
}

/// Why a lookup failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DnsFailure {
    /// The name does not exist.
    #[error("NXDOMAIN: the name does not exist")]
    NxDomain,
    /// No answer within the timeout.
    #[error("timed out")]
    Timeout,
    /// The server failed to answer (`SERVFAIL`).
    #[error("SERVFAIL: the server failed to resolve the query")]
    ServFail,
    /// The server refused to answer.
    #[error("REFUSED: the server refused the query")]
    Refused,
    /// The server could not be reached.
    #[error("network error: {0}")]
    Network(String),
    /// The input is not something that can be looked up.
    #[error("invalid name: {0}")]
    InvalidName(String),
    /// The resolver could not be set up (no system DNS servers, bad custom list, ...).
    #[error("resolver configuration error: {0}")]
    Config(String),
    /// Anything else the resolver reported.
    #[error("{0}")]
    Other(String),
}

/// Which servers answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ResolverChoice {
    /// The servers Windows (or `resolv.conf`) is configured with.
    #[default]
    System,
    /// Cloudflare, 1.1.1.1 and 1.0.0.1.
    Cloudflare,
    /// Google, 8.8.8.8 and 8.8.4.4.
    Google,
    /// These servers (1 to [`MAX_CUSTOM_SERVERS`], port 53).
    Custom(Vec<IpAddr>),
}

impl ResolverChoice {
    /// The explicit server list, or `None` for [`ResolverChoice::System`].
    pub fn servers(&self) -> Result<Option<Vec<IpAddr>>, DnsFailure> {
        match self {
            ResolverChoice::System => Ok(None),
            ResolverChoice::Cloudflare => Ok(Some(vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ])),
            ResolverChoice::Google => Ok(Some(vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            ])),
            ResolverChoice::Custom(list) => {
                if list.is_empty() {
                    return Err(DnsFailure::Config("no DNS server given".to_owned()));
                }
                if list.len() > MAX_CUSTOM_SERVERS {
                    return Err(DnsFailure::Config(format!(
                        "at most {MAX_CUSTOM_SERVERS} DNS servers are allowed"
                    )));
                }
                for ip in list {
                    if ip.is_unspecified() || ip.is_multicast() {
                        return Err(DnsFailure::Config(format!(
                            "{ip} is not a usable DNS server"
                        )));
                    }
                    if let IpAddr::V4(v4) = ip {
                        if v4.is_broadcast() {
                            return Err(DnsFailure::Config(format!(
                                "{ip} is not a usable DNS server"
                            )));
                        }
                    }
                }
                Ok(Some(list.clone()))
            }
        }
    }
}

/// Lookup parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOptions {
    /// Which servers to ask.
    pub resolver: ResolverChoice,
    /// Per-query timeout (default 5 s, clamped to 100 ms..=15 s).
    pub timeout: Duration,
}

impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            resolver: ResolverChoice::System,
            timeout: DEFAULT_DNS_TIMEOUT,
        }
    }
}

impl DnsOptions {
    /// The timeout forced into its supported range.
    pub fn effective_timeout(&self) -> Duration {
        self.timeout.clamp(MIN_DNS_TIMEOUT, MAX_DNS_TIMEOUT)
    }
}

/// The outcome of a lookup that got at least some answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLookup {
    /// The name or address that was looked up, as given (trimmed).
    pub query: String,
    /// The type asked for.
    pub requested: DnsRecordType,
    /// Records found, grouped by type in the order of [`DnsRecordType::CONCRETE`].
    pub records: Vec<DnsRecord>,
    /// Types that failed while others succeeded (only possible for `ALL`).
    pub errors: Vec<(DnsRecordType, DnsFailure)>,
    /// How long the lookup took.
    pub elapsed: Duration,
}

/// Performs one query for one concrete record type.
pub trait DnsBackend: Send + Sync {
    /// Query `name` (fully qualified, trailing dot) for `record_type`, which is never
    /// [`DnsRecordType::All`]. Return only records of that type; an empty list means "the name
    /// exists but has none". Must not rely on a cache: results are for diagnostics.
    fn query(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> impl Future<Output = Result<Vec<DnsRecord>, DnsFailure>> + Send;
}

/// Lookup logic on top of a backend.
#[derive(Debug, Clone)]
pub struct DnsClient<B> {
    backend: B,
    timeout: Duration,
}

impl<B: DnsBackend> DnsClient<B> {
    /// Wrap `backend`; every query is abandoned after `timeout` (clamped to 100 ms..=15 s).
    pub fn new(backend: B, timeout: Duration) -> Self {
        Self {
            backend,
            timeout: timeout.clamp(MIN_DNS_TIMEOUT, MAX_DNS_TIMEOUT),
        }
    }

    async fn one(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<Vec<DnsRecord>, DnsFailure> {
        match tokio::time::timeout(self.timeout, self.backend.query(name, record_type)).await {
            Ok(r) => r,
            Err(_) => Err(DnsFailure::Timeout),
        }
    }

    /// Look up `input` (a host name or an IP address) for `record_type`.
    pub async fn lookup(
        &self,
        input: &str,
        record_type: DnsRecordType,
    ) -> Result<DnsLookup, DnsFailure> {
        let query = input.trim().to_owned();
        let started = Instant::now();

        let (qname, types): (String, Vec<DnsRecordType>) = if let Ok(ip) = query.parse::<IpAddr>() {
            match record_type {
                DnsRecordType::Ptr | DnsRecordType::All => {
                    (reverse_name(ip), vec![DnsRecordType::Ptr])
                }
                other => {
                    return Err(DnsFailure::InvalidName(format!(
                        "{other} records are looked up by host name, not by IP address"
                    )))
                }
            }
        } else {
            let name = normalize_name(&query)?;
            let types = match record_type {
                DnsRecordType::All => DnsRecordType::CONCRETE.to_vec(),
                single => vec![single],
            };
            (name, types)
        };

        let outcomes = if types.len() == 1 {
            vec![(types[0], self.one(&qname, types[0]).await)]
        } else {
            let t = |i: usize| types[i];
            let (a, aaaa, mx, txt, ns, soa, cname, ptr) = tokio::join!(
                self.one(&qname, t(0)),
                self.one(&qname, t(1)),
                self.one(&qname, t(2)),
                self.one(&qname, t(3)),
                self.one(&qname, t(4)),
                self.one(&qname, t(5)),
                self.one(&qname, t(6)),
                self.one(&qname, t(7)),
            );
            types
                .iter()
                .copied()
                .zip([a, aaaa, mx, txt, ns, soa, cname, ptr])
                .collect()
        };

        let (records, errors) = if outcomes.len() == 1 {
            // A single query: its failure is the failure.
            match outcomes.into_iter().next() {
                Some((_, Ok(records))) => (records, Vec::new()),
                Some((_, Err(e))) => return Err(e),
                None => (Vec::new(), Vec::new()),
            }
        } else {
            aggregate_all(outcomes)?
        };

        Ok(DnsLookup {
            query,
            requested: record_type,
            records,
            errors,
            elapsed: started.elapsed(),
        })
    }

    /// The first PTR name of `ip`, if it has one.
    pub async fn reverse(&self, ip: IpAddr) -> Option<String> {
        let records = self.one(&reverse_name(ip), DnsRecordType::Ptr).await.ok()?;
        records.into_iter().find_map(|r| match r.data {
            DnsRecordData::Ptr(name) => Some(name),
            _ => None,
        })
    }
}

impl<B: DnsBackend + 'static> ReverseLookup for DnsClient<B> {
    async fn reverse(&self, ip: IpAddr) -> Option<String> {
        DnsClient::reverse(self, ip).await
    }
}

/// Per-type failures that did not stop an `ALL` lookup.
pub type TypeErrors = Vec<(DnsRecordType, DnsFailure)>;

/// Merge the per-type outcomes of an `ALL` lookup (see the module docs for the rules).
pub fn aggregate_all(
    outcomes: Vec<(DnsRecordType, Result<Vec<DnsRecord>, DnsFailure>)>,
) -> Result<(Vec<DnsRecord>, TypeErrors), DnsFailure> {
    let mut records = Vec::new();
    let mut errors = Vec::new();
    let mut succeeded = 0usize;
    for (rtype, outcome) in outcomes {
        match outcome {
            Ok(mut found) => {
                succeeded += 1;
                records.append(&mut found);
            }
            Err(DnsFailure::NxDomain) => return Err(DnsFailure::NxDomain),
            Err(e) => errors.push((rtype, e)),
        }
    }
    if succeeded == 0 {
        if let Some((_, first)) = errors.into_iter().next() {
            return Err(first);
        }
        return Ok((Vec::new(), Vec::new()));
    }
    Ok((records, errors))
}

/// The reverse-lookup name of `ip` with a trailing dot:
/// `4.3.2.1.in-addr.arpa.` or the 32-nibble `ip6.arpa.` form.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(32 * 2 + 10);
            for byte in v6.octets().iter().rev() {
                out.push(nibble(byte & 0x0f));
                out.push('.');
                out.push(nibble(byte >> 4));
                out.push('.');
            }
            out.push_str("ip6.arpa.");
            out
        }
    }
}

fn nibble(v: u8) -> char {
    char::from_digit(u32::from(v), 16).unwrap_or('0')
}

/// Validate a host name and return it fully qualified (single trailing dot).
pub fn normalize_name(input: &str) -> Result<String, DnsFailure> {
    let name = input.trim();
    let bare = name.strip_suffix('.').unwrap_or(name);
    if bare.is_empty() {
        return Err(DnsFailure::InvalidName("the name is empty".to_owned()));
    }
    if bare.chars().count() > 253 {
        return Err(DnsFailure::InvalidName(
            "the name is longer than 253 characters".to_owned(),
        ));
    }
    if bare.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(DnsFailure::InvalidName(
            "the name contains spaces or control characters".to_owned(),
        ));
    }
    if bare.split('.').any(str::is_empty) {
        return Err(DnsFailure::InvalidName(
            "the name has an empty label".to_owned(),
        ));
    }
    if bare.split('.').any(|l| l.chars().count() > 63) {
        return Err(DnsFailure::InvalidName(
            "a label is longer than 63 characters".to_owned(),
        ));
    }
    Ok(format!("{bare}."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeDnsBackend;

    fn rec(name: &str, data: DnsRecordData) -> DnsRecord {
        DnsRecord {
            name: name.to_owned(),
            ttl: 300,
            data,
        }
    }

    fn a(name: &str, ip: &str) -> DnsRecord {
        rec(name, DnsRecordData::A(ip.parse().unwrap()))
    }

    /// example.com has A, AAAA, MX, TXT, NS, SOA; no CNAME, no PTR.
    fn zone() -> FakeDnsBackend {
        FakeDnsBackend::new(|name, t| {
            assert_eq!(name, "example.com.");
            Ok(match t {
                DnsRecordType::A => {
                    vec![a("example.com", "192.0.2.1"), a("example.com", "192.0.2.2")]
                }
                DnsRecordType::Aaaa => vec![rec(
                    "example.com",
                    DnsRecordData::Aaaa("2001:db8::1".parse().unwrap()),
                )],
                DnsRecordType::Mx => vec![rec(
                    "example.com",
                    DnsRecordData::Mx {
                        preference: 10,
                        exchange: "mail.example.com".into(),
                    },
                )],
                DnsRecordType::Txt => {
                    vec![rec("example.com", DnsRecordData::Txt("v=spf1 -all".into()))]
                }
                DnsRecordType::Ns => vec![rec(
                    "example.com",
                    DnsRecordData::Ns("ns1.example.com".into()),
                )],
                DnsRecordType::Soa => vec![rec(
                    "example.com",
                    DnsRecordData::Soa {
                        mname: "ns1.example.com".into(),
                        rname: "hostmaster.example.com".into(),
                        serial: 1,
                        refresh: 7200,
                        retry: 900,
                        expire: 1_209_600,
                        minimum: 300,
                    },
                )],
                DnsRecordType::Cname | DnsRecordType::Ptr => vec![],
                DnsRecordType::All => panic!("backend must never see ALL"),
            })
        })
    }

    fn client(b: FakeDnsBackend) -> DnsClient<FakeDnsBackend> {
        DnsClient::new(b, Duration::from_secs(5))
    }

    #[tokio::test(start_paused = true)]
    async fn all_returns_every_type_with_data_and_no_empty_ones() {
        let c = client(zone());
        let r = c.lookup("example.com", DnsRecordType::All).await.unwrap();
        let types: Vec<_> = r.records.iter().map(DnsRecord::record_type).collect();
        assert_eq!(
            types,
            vec![
                DnsRecordType::A,
                DnsRecordType::A,
                DnsRecordType::Aaaa,
                DnsRecordType::Mx,
                DnsRecordType::Txt,
                DnsRecordType::Ns,
                DnsRecordType::Soa
            ]
        );
        assert!(r.errors.is_empty());
        assert_eq!(r.requested, DnsRecordType::All);
        // Every concrete type queried exactly once, never ALL/ANY.
        let mut asked: Vec<_> = c.backend.queries().into_iter().map(|(_, t)| t).collect();
        asked.sort_by_key(|t| t.as_str());
        let mut expected = DnsRecordType::CONCRETE.to_vec();
        expected.sort_by_key(|t| t.as_str());
        assert_eq!(asked, expected);
    }

    #[tokio::test(start_paused = true)]
    async fn single_type_and_trailing_dot_normalisation() {
        let c = client(zone());
        let r = c
            .lookup("  example.com. ", DnsRecordType::Mx)
            .await
            .unwrap();
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.query, "example.com.");
        assert_eq!(
            c.backend.queries(),
            vec![("example.com.".to_owned(), DnsRecordType::Mx)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_data_is_ok_and_empty() {
        let c = client(zone());
        let r = c.lookup("example.com", DnsRecordType::Cname).await.unwrap();
        assert!(r.records.is_empty() && r.errors.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn nxdomain_on_any_type_fails_the_whole_all_lookup() {
        let c = client(FakeDnsBackend::new(|_, t| match t {
            DnsRecordType::A => Ok(vec![a("x.test", "192.0.2.1")]),
            DnsRecordType::Mx => Err(DnsFailure::NxDomain),
            _ => Ok(vec![]),
        }));
        assert_eq!(
            c.lookup("x.test", DnsRecordType::All).await,
            Err(DnsFailure::NxDomain)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn nxdomain_single_type() {
        let c = client(FakeDnsBackend::new(|_, _| Err(DnsFailure::NxDomain)));
        assert_eq!(
            c.lookup("nope.test", DnsRecordType::A).await,
            Err(DnsFailure::NxDomain)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn partial_failures_are_reported_next_to_the_records() {
        let c = client(FakeDnsBackend::new(|_, t| match t {
            DnsRecordType::A => Ok(vec![a("x.test", "192.0.2.1")]),
            DnsRecordType::Txt => Err(DnsFailure::Timeout),
            DnsRecordType::Soa => Err(DnsFailure::ServFail),
            _ => Ok(vec![]),
        }));
        let r = c.lookup("x.test", DnsRecordType::All).await.unwrap();
        assert_eq!(r.records.len(), 1);
        assert_eq!(
            r.errors,
            vec![
                (DnsRecordType::Txt, DnsFailure::Timeout),
                (DnsRecordType::Soa, DnsFailure::ServFail)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn all_types_failing_is_an_error() {
        let c = client(FakeDnsBackend::new(|_, _| Err(DnsFailure::ServFail)));
        assert_eq!(
            c.lookup("x.test", DnsRecordType::All).await,
            Err(DnsFailure::ServFail)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mixed_no_data_and_errors_without_records_is_ok_with_errors() {
        let c = client(FakeDnsBackend::new(|_, t| match t {
            DnsRecordType::Txt => Err(DnsFailure::Timeout),
            _ => Ok(vec![]),
        }));
        let r = c.lookup("x.test", DnsRecordType::All).await.unwrap();
        assert!(r.records.is_empty());
        assert_eq!(r.errors, vec![(DnsRecordType::Txt, DnsFailure::Timeout)]);
    }

    #[tokio::test(start_paused = true)]
    async fn single_type_failures_propagate() {
        for failure in [
            DnsFailure::Timeout,
            DnsFailure::ServFail,
            DnsFailure::Refused,
            DnsFailure::Network("unreachable".into()),
        ] {
            let f = failure.clone();
            let c = client(FakeDnsBackend::new(move |_, _| Err(f.clone())));
            assert_eq!(c.lookup("x.test", DnsRecordType::Txt).await, Err(failure));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_backend_times_out_once_for_all_types_in_parallel() {
        let c = DnsClient::new(
            FakeDnsBackend::new(|_, _| Ok(vec![])).with_delay(Duration::from_secs(60)),
            Duration::from_secs(2),
        );
        let t0 = Instant::now();
        let r = c.lookup("x.test", DnsRecordType::All).await;
        assert_eq!(r, Err(DnsFailure::Timeout));
        assert_eq!(
            t0.elapsed(),
            Duration::from_secs(2),
            "queries run concurrently"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_is_clamped() {
        let c = DnsClient::new(
            FakeDnsBackend::new(|_, _| Ok(vec![])),
            Duration::from_secs(900),
        );
        assert_eq!(c.timeout, MAX_DNS_TIMEOUT);
        let c = DnsClient::new(FakeDnsBackend::new(|_, _| Ok(vec![])), Duration::ZERO);
        assert_eq!(c.timeout, MIN_DNS_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn ip_input_becomes_a_ptr_query() {
        let c = client(FakeDnsBackend::new(|name, t| {
            assert_eq!(t, DnsRecordType::Ptr);
            assert_eq!(name, "4.3.2.1.in-addr.arpa.");
            Ok(vec![rec(
                name.trim_end_matches('.'),
                DnsRecordData::Ptr("host.example.com".into()),
            )])
        }));
        for rt in [DnsRecordType::Ptr, DnsRecordType::All] {
            let r = c.lookup("1.2.3.4", rt).await.unwrap();
            assert_eq!(r.records.len(), 1);
        }
        assert_eq!(
            c.backend.queries().len(),
            2,
            "ALL on an IP is a single PTR query"
        );
        assert!(matches!(
            c.lookup("1.2.3.4", DnsRecordType::A).await,
            Err(DnsFailure::InvalidName(_))
        ));
        assert_eq!(
            c.backend.queries().len(),
            2,
            "rejected before anything is sent"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reverse_helper_and_reverse_lookup_trait() {
        let c = client(FakeDnsBackend::new(|name, _| {
            Ok(if name == "4.3.2.1.in-addr.arpa." {
                vec![rec("x", DnsRecordData::Ptr("one.example.net".into()))]
            } else {
                vec![]
            })
        }));
        assert_eq!(
            c.reverse("1.2.3.4".parse().unwrap()).await.as_deref(),
            Some("one.example.net")
        );
        assert_eq!(c.reverse("1.2.3.5".parse().unwrap()).await, None);
        let via_trait = ReverseLookup::reverse(&c, "1.2.3.4".parse().unwrap()).await;
        assert_eq!(via_trait.as_deref(), Some("one.example.net"));
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("192.0.2.45".parse().unwrap()),
            "45.2.0.192.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
        assert_eq!(
            reverse_name("::1".parse().unwrap()),
            format!("1.{}ip6.arpa.", "0.".repeat(31))
        );
    }

    #[test]
    fn name_validation() {
        assert_eq!(normalize_name("Example.COM").unwrap(), "Example.COM.");
        assert_eq!(normalize_name("example.com.").unwrap(), "example.com.");
        assert_eq!(normalize_name("münchen.de").unwrap(), "münchen.de.");
        for bad in [
            "",
            " ",
            ".",
            "a..b",
            "a b.com",
            "a\tb.com",
            &"a".repeat(64),
            &vec!["a"; 128].join("."),
        ] {
            assert!(
                matches!(normalize_name(bad), Err(DnsFailure::InvalidName(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_names_never_reach_the_backend() {
        let c = client(FakeDnsBackend::new(|_, _| Ok(vec![])));
        assert!(matches!(
            c.lookup("", DnsRecordType::A).await,
            Err(DnsFailure::InvalidName(_))
        ));
        assert!(c.backend.queries().is_empty());
    }

    #[test]
    fn record_type_parsing_and_display() {
        for t in DnsRecordType::CONCRETE
            .into_iter()
            .chain([DnsRecordType::All])
        {
            assert_eq!(
                t.as_str()
                    .to_ascii_lowercase()
                    .parse::<DnsRecordType>()
                    .unwrap(),
                t
            );
            assert_eq!(t.to_string(), t.as_str());
        }
        assert!("ANY".parse::<DnsRecordType>().is_err());
    }

    #[test]
    fn resolver_choices() {
        assert_eq!(ResolverChoice::System.servers().unwrap(), None);
        assert_eq!(
            ResolverChoice::Cloudflare.servers().unwrap().unwrap()[0],
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            ResolverChoice::Google.servers().unwrap().unwrap()[0],
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        let ok = ResolverChoice::Custom(vec![
            "9.9.9.9".parse().unwrap(),
            "2620:fe::fe".parse().unwrap(),
        ]);
        assert_eq!(ok.servers().unwrap().unwrap().len(), 2);
        for bad in [
            vec![],
            vec!["0.0.0.0".parse().unwrap()],
            vec!["224.0.0.1".parse().unwrap()],
            vec!["255.255.255.255".parse().unwrap()],
            vec!["::".parse().unwrap()],
            (1..=5)
                .map(|i| format!("10.0.0.{i}").parse().unwrap())
                .collect(),
        ] {
            assert!(matches!(
                ResolverChoice::Custom(bad).servers(),
                Err(DnsFailure::Config(_))
            ));
        }
    }

    #[test]
    fn record_values_render_like_dig() {
        assert_eq!(
            DnsRecordData::Mx {
                preference: 10,
                exchange: "mx.example.com".into()
            }
            .value(),
            "10 mx.example.com"
        );
        assert_eq!(
            DnsRecordData::A("192.0.2.1".parse().unwrap()).value(),
            "192.0.2.1"
        );
        assert_eq!(
            DnsRecordData::Soa {
                mname: "ns".into(),
                rname: "h".into(),
                serial: 5,
                refresh: 1,
                retry: 2,
                expire: 3,
                minimum: 4
            }
            .value(),
            "ns h 5 1 2 3 4"
        );
    }

    #[test]
    fn options_timeout_clamp() {
        let o = DnsOptions {
            timeout: Duration::from_secs(99),
            ..DnsOptions::default()
        };
        assert_eq!(o.effective_timeout(), MAX_DNS_TIMEOUT);
        assert_eq!(
            DnsOptions::default().effective_timeout(),
            DEFAULT_DNS_TIMEOUT
        );
    }
}
