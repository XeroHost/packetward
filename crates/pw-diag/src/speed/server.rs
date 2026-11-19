// SPDX-License-Identifier: GPL-3.0-or-later
//! Speed-test servers: the node list entries, custom server URLs, the `/info` document and test ids.
//!
//! Hostnames are never invented: a node's host comes verbatim from the node list, a custom server's from the user.
//! Both are validated as plain ASCII DNS names or IP literals. XeroHost nodes are always reached over `https`;
//! `http` exists only for a custom server the user typed with an explicit `http://` (a LAN box, loopback).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::error::SpeedError;

/// An entry of the XeroHost node list (`nodes.json`). A plain struct on purpose: this crate does not depend on
/// `pw-intel`, the engine maps `pw_intel::Node` to this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedNode {
    /// Stable node id (`mia`, `dal`, ...).
    pub id: String,
    /// Display name.
    pub name: String,
    /// DNS name carrying the TLS certificate.
    pub host: String,
    /// Public port.
    pub port: u16,
}

/// URL scheme of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// TLS. The default and the only scheme of node-list servers.
    Https,
    /// Cleartext. Only for an explicit custom server.
    Http,
}

impl Scheme {
    /// `"https"` or `"http"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

/// A validated server address plus how to show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEndpoint {
    /// Stable id: the node id, or the authority for a custom server.
    pub id: String,
    /// Display name.
    pub name: String,
    /// `https` or `http`.
    pub scheme: Scheme,
    /// Lowercase host name or IP literal (IPv6 without brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// `true` for a server the user added.
    pub custom: bool,
}

impl ServerEndpoint {
    /// A node of the XeroHost list: always `https`.
    pub fn from_node(node: &SpeedNode) -> Result<Self, SpeedError> {
        let host = normalize_host(&node.host)?;
        if node.port == 0 {
            return Err(invalid("the port must be 1-65535"));
        }
        if node.id.is_empty() || node.id.len() > 64 {
            return Err(invalid("the node id must be 1-64 characters"));
        }
        let name = if node.name.trim().is_empty() {
            node.id.clone()
        } else {
            node.name.trim().chars().take(80).collect()
        };
        Ok(Self {
            id: node.id.clone(),
            name,
            scheme: Scheme::Https,
            host,
            port: node.port,
            custom: false,
        })
    }

    /// A user-supplied server: `https://host[:port]`, `http://host[:port]` (explicit cleartext), or a bare
    /// `host[:port]` which means `https`. No path, query, fragment or credentials.
    pub fn custom(input: &str) -> Result<Self, SpeedError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(invalid("the server address is empty"));
        }
        let (scheme, rest) = match input.split_once("://") {
            Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
                "https" => (Scheme::Https, rest),
                "http" => (Scheme::Http, rest),
                _ => return Err(invalid("only http:// and https:// servers are supported")),
            },
            None => (Scheme::Https, input),
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty()
            || rest.contains(['/', '?', '#', '@', '\\'])
            || rest.contains(char::is_whitespace)
        {
            return Err(invalid(
                "a server address is scheme://host[:port] with no path, query or credentials",
            ));
        }
        let (host, port) = split_authority(rest)?;
        let host = normalize_host(host)?;
        let port = match port {
            Some(port) => port,
            None => match scheme {
                Scheme::Https => 443,
                Scheme::Http => 80,
            },
        };
        let mut endpoint = Self {
            id: String::new(),
            name: String::new(),
            scheme,
            host,
            port,
            custom: true,
        };
        let authority = endpoint.authority();
        endpoint.id = authority.clone();
        endpoint.name = authority;
        Ok(endpoint)
    }

    /// `host:port`, with brackets around an IPv6 literal.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Absolute URL of `path_and_query` (which must start with `/`) on this server.
    pub fn url(&self, path_and_query: &str) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.authority(),
            path_and_query
        )
    }

    /// Whether the server is on this machine (`localhost`, `127.0.0.0/8`, `::1`). The real transport never sends
    /// loopback traffic through a proxy.
    pub fn is_loopback(&self) -> bool {
        self.host == "localhost" || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// Whether traffic to this server is unencrypted.
    pub fn is_cleartext(&self) -> bool {
        self.scheme == Scheme::Http
    }
}

/// An input that was not turned into a server, for the UI to explain. Never echoes the input (it could contain a
/// pasted credential).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedServer {
    /// Index in the list it came from (nodes first, then custom URLs, each list counted separately).
    pub index: usize,
    /// `true` if it was a custom URL, `false` for a node.
    pub custom: bool,
    /// Why.
    pub reason: SpeedError,
}

/// Servers ready to measure, plus what was rejected. An empty list is valid ("custom servers only").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidates {
    /// Usable servers, nodes first, then custom ones; duplicates removed.
    pub servers: Vec<ServerEndpoint>,
    /// Entries that were refused.
    pub rejected: Vec<RejectedServer>,
}

impl Candidates {
    /// Validate a node list and a list of custom URLs.
    pub fn from_lists(nodes: &[SpeedNode], custom_urls: &[String]) -> Self {
        let mut out = Self::default();
        for (index, node) in nodes.iter().enumerate() {
            match ServerEndpoint::from_node(node) {
                Ok(server) => out.push(server),
                Err(reason) => out.rejected.push(RejectedServer {
                    index,
                    custom: false,
                    reason,
                }),
            }
        }
        for (index, url) in custom_urls.iter().enumerate() {
            match ServerEndpoint::custom(url) {
                Ok(server) => out.push(server),
                Err(reason) => out.rejected.push(RejectedServer {
                    index,
                    custom: true,
                    reason,
                }),
            }
        }
        out
    }

    fn push(&mut self, server: ServerEndpoint) {
        let key = (server.scheme, server.host.as_str(), server.port);
        if !self
            .servers
            .iter()
            .any(|s| (s.scheme, s.host.as_str(), s.port) == key)
        {
            self.servers.push(server);
        }
    }
}

fn invalid(text: &str) -> SpeedError {
    SpeedError::InvalidInput(text.to_owned())
}

/// Split `host[:port]` / `[v6][:port]`.
fn split_authority(rest: &str) -> Result<(&str, Option<u16>), SpeedError> {
    if let Some(inner) = rest.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or_else(|| invalid("unterminated [IPv6] address"))?;
        return match after {
            "" => Ok((host, None)),
            _ => match after.strip_prefix(':') {
                Some(port) => Ok((host, Some(parse_port(port)?))),
                None => Err(invalid("unexpected text after the [IPv6] address")),
            },
        };
    }
    match rest.split_once(':') {
        None => Ok((rest, None)),
        Some((host, port)) => {
            if port.contains(':') {
                return Err(invalid("an IPv6 address must be written in [brackets]"));
            }
            Ok((host, Some(parse_port(port)?)))
        }
    }
}

fn parse_port(text: &str) -> Result<u16, SpeedError> {
    match text.parse::<u16>() {
        Ok(port) if port != 0 && text.bytes().all(|b| b.is_ascii_digit()) => Ok(port),
        _ => Err(invalid("the port must be 1-65535")),
    }
}

/// Lowercase ASCII DNS name or IP literal; refuses placeholders from the node-list template.
fn normalize_host(host: &str) -> Result<String, SpeedError> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(invalid("invalid host name"));
    }
    if host.starts_with("replace-with") {
        return Err(invalid("placeholder host name"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if labels_ok {
        Ok(host)
    } else {
        Err(invalid("invalid host name"))
    }
}

/// Limits a server publishes in `/info`. `0` means unlimited, exactly as in the server's configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerLimits {
    /// Concurrent tests per client IP.
    pub max_concurrent_tests_per_ip: u64,
    /// Parallel streams inside one test.
    pub max_streams_per_test: u64,
    /// Concurrent tests on the whole node.
    pub max_concurrent_tests_global: u64,
    /// Request rate per client IP.
    pub requests_per_minute_per_ip: u64,
    /// Bytes per client IP and hour.
    pub hourly_bytes_per_ip: u64,
    /// Bytes per client IP and day.
    pub daily_bytes_per_ip: u64,
    /// Hard cap of one transfer.
    pub max_transfer_secs: u64,
}

/// The `/info` document of a speed server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerInfo {
    /// Protocol revision.
    pub protocol: u32,
    /// Server software version.
    pub server_version: String,
    /// Node id.
    pub node_id: String,
    /// Node display name.
    pub node_name: String,
    /// Free-text location.
    pub location: String,
    /// The requesting client's public IP as the server sees it.
    pub client_ip: String,
    /// Largest `bytes=` of `/download` (`0` = unknown).
    pub max_download_bytes: u64,
    /// Largest upload body (`0` = unknown).
    pub max_upload_bytes: u64,
    /// Protection limits.
    pub limits: ServerLimits,
}

impl ServerInfo {
    /// `client_ip` as an address; `None` when the server sent nothing usable.
    pub fn client_ip_addr(&self) -> Option<IpAddr> {
        self.client_ip.trim().parse().ok()
    }

    /// Parallel streams allowed for one test (`None` = not limited / unknown).
    pub fn stream_limit(&self) -> Option<usize> {
        match self.limits.max_streams_per_test {
            0 => None,
            n => Some(usize::try_from(n).unwrap_or(usize::MAX)),
        }
    }
}

/// Whether `id` is acceptable as the server's `?test=` value: 1-64 characters of `A-Za-z0-9_-`.
pub fn valid_test_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A fresh random-looking run id (32 hex characters) for `?test=`. Not a secret; it only groups the parallel
/// streams of one run on the server. Built from the std randomly-seeded hasher, a counter and the clock, so
/// there is no `rand` dependency.
pub fn new_test_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut parts = [0u64; 2];
    for (salt, part) in parts.iter_mut().enumerate() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(nanos);
        hasher.write_u64(counter);
        hasher.write_usize(salt);
        *part = hasher.finish();
    }
    format!("{:016x}{:016x}", parts[0], parts[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(host: &str, port: u16) -> SpeedNode {
        SpeedNode {
            id: "mia".into(),
            name: "Miami".into(),
            host: host.into(),
            port,
        }
    }

    #[test]
    fn nodes_are_https_and_keep_the_listed_host() {
        let server = ServerEndpoint::from_node(&node("Speed.Example.com", 443)).unwrap();
        assert_eq!(server.scheme, Scheme::Https);
        assert_eq!(server.host, "speed.example.com");
        assert_eq!(server.url("/ping"), "https://speed.example.com:443/ping");
        assert!(!server.custom);
    }

    #[test]
    fn placeholder_and_bad_nodes_are_refused() {
        for host in [
            "REPLACE-WITH-REAL-HOSTNAME",
            "",
            "bad host",
            "-a.example",
            "a..b",
            "ex_ample.com",
            "caf\u{e9}.example",
        ] {
            assert!(
                ServerEndpoint::from_node(&node(host, 443)).is_err(),
                "{host:?}"
            );
        }
        assert!(ServerEndpoint::from_node(&node("a.example", 0)).is_err());
    }

    #[test]
    fn custom_urls_parse() {
        let s = ServerEndpoint::custom("https://speed.example.com").unwrap();
        assert_eq!((s.scheme, s.port, s.custom), (Scheme::Https, 443, true));
        let s = ServerEndpoint::custom("speed.example.com:8443").unwrap();
        assert_eq!((s.scheme, s.port), (Scheme::Https, 8443));
        let s = ServerEndpoint::custom("http://127.0.0.1:8080/").unwrap();
        assert_eq!((s.scheme, s.port), (Scheme::Http, 8080));
        assert!(s.is_loopback() && s.is_cleartext());
        assert_eq!(s.url("/ping"), "http://127.0.0.1:8080/ping");
        let s = ServerEndpoint::custom("http://[::1]:9000").unwrap();
        assert_eq!(s.authority(), "[::1]:9000");
        assert_eq!(s.url("/info"), "http://[::1]:9000/info");
        assert!(s.is_loopback());
        assert!(!ServerEndpoint::custom("https://example.com")
            .unwrap()
            .is_loopback());
        assert_eq!(
            ServerEndpoint::custom("http://example.com").unwrap().port,
            80
        );
    }

    #[test]
    fn custom_urls_with_paths_credentials_or_odd_syntax_are_refused() {
        for bad in [
            "",
            "ftp://example.com",
            "https://user:pw@example.com",
            "https://example.com/path",
            "https://example.com?x=1",
            "https://example.com:0",
            "https://example.com:99999",
            "https://example.com:",
            "https://example.com:80a",
            "::1",
            "[::1",
            "https://exa mple.com",
            "https://",
        ] {
            assert!(ServerEndpoint::custom(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_rejected_server_never_echoes_its_input() {
        let candidates = Candidates::from_lists(&[], &["https://user:hunter2@example.com".into()]);
        assert!(candidates.servers.is_empty());
        assert_eq!(candidates.rejected.len(), 1);
        assert!(!format!("{:?}", candidates.rejected).contains("hunter2"));
    }

    #[test]
    fn candidates_dedupe_and_may_be_empty() {
        assert!(Candidates::from_lists(&[], &[]).servers.is_empty());
        let c = Candidates::from_lists(
            &[node("a.example.com", 443), node("A.EXAMPLE.com", 443)],
            &[
                "https://a.example.com".into(),
                "http://a.example.com".into(),
            ],
        );
        assert_eq!(c.servers.len(), 2);
        assert!(c.servers.iter().any(|s| s.scheme == Scheme::Http));
    }

    #[test]
    fn test_ids_are_valid_and_distinct() {
        let a = new_test_id();
        let b = new_test_id();
        assert!(valid_test_id(&a) && a.len() == 32);
        assert_ne!(a, b);
        assert!(!valid_test_id("") && !valid_test_id("a b") && !valid_test_id(&"x".repeat(65)));
    }

    #[test]
    fn info_parses_the_server_document_and_tolerates_missing_fields() {
        let json = r#"{"protocol":1,"server_version":"0.1.0","node_id":"mia","node_name":"Miami",
            "location":"Miami, US","client_ip":"203.0.113.9","max_download_bytes":53687091200,
            "max_upload_bytes":10737418240,"limits":{"max_concurrent_tests_per_ip":2,
            "max_streams_per_test":8,"max_concurrent_tests_global":64,"requests_per_minute_per_ip":600,
            "hourly_bytes_per_ip":107374182400,"daily_bytes_per_ip":322122547200,"max_transfer_secs":14400}}"#;
        let info: ServerInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.client_ip_addr(), Some("203.0.113.9".parse().unwrap()));
        assert_eq!(info.stream_limit(), Some(8));
        assert_eq!(info.limits.hourly_bytes_per_ip, 100 << 30);
        let sparse: ServerInfo = serde_json::from_str(r#"{"client_ip":"not an ip"}"#).unwrap();
        assert_eq!(sparse.client_ip_addr(), None);
        assert_eq!(sparse.stream_limit(), None);
    }
}
