// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The XeroHost node list (`nodes.json`), used for speed-test and MTR defaults.
//!
//! The file lives in the public repository `XeroHost/packetward-blocklist`. It is **not signed**, so it is
//! validated strictly: hostnames only (or public IP literals), sane ports, no reserved addresses. Until the real
//! hostnames exist the file holds `REPLACE-WITH-…` placeholders and an empty list is equally valid: both simply
//! mean "custom servers only". No hostname is ever invented here.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::net::is_public_ip;
use crate::{FetchError, FetchRequest, Fetcher};

/// Raw GitHub URL of `nodes.json`. Placeholder: the branch name (`main`) is an assumption until the repository
/// exists, and `docs/RELEASE-KEYS.md` §3 describes how it is created.
pub const NODES_URL: &str =
    "https://raw.githubusercontent.com/XeroHost/packetward-blocklist/main/nodes.json";
/// Largest accepted `nodes.json`.
pub const MAX_NODES_BYTES: usize = 64 * 1024;
/// Most nodes kept from one file.
pub const MAX_NODES: usize = 64;
/// Format version this code understands.
pub const NODES_FORMAT_VERSION: u32 = 1;

const PLACEHOLDER_PREFIX: &str = "REPLACE-WITH";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
}

/// Why one entry was not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedNode {
    /// Index in the file.
    pub index: usize,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SkipReason {
    /// The hostname is still a `REPLACE-WITH-…` placeholder (valid file, nothing usable yet).
    #[error("placeholder hostname")]
    Placeholder,
    #[error("invalid id")]
    InvalidId,
    #[error("duplicate id")]
    DuplicateId,
    #[error("invalid name")]
    InvalidName,
    #[error("invalid hostname")]
    InvalidHost,
    #[error("port must be 1-65535")]
    InvalidPort,
    #[error("more than the allowed number of nodes")]
    TooMany,
}

/// A parsed `nodes.json`: usable nodes plus the entries that were skipped (for diagnostics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeList {
    pub nodes: Vec<Node>,
    pub skipped: Vec<SkippedNode>,
}

impl NodeList {
    /// An empty list means "custom servers only".
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodesError {
    #[error("nodes.json is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("nodes.json is not valid JSON: {0}")]
    Json(String),
    #[error("unsupported nodes.json version {found} (supported: {NODES_FORMAT_VERSION})")]
    UnsupportedVersion { found: u32 },
    #[error("download failed: {0}")]
    Fetch(#[from] FetchError),
    #[error("the server answered HTTP {0}")]
    HttpStatus(u16),
}

#[derive(Deserialize)]
struct RawFile {
    version: u32,
    #[serde(default)]
    nodes: Vec<RawNode>,
}

// Unknown fields are ignored for forward compatibility; every known field is optional here so that one malformed
// entry skips itself instead of rejecting the whole file.
#[derive(Deserialize)]
struct RawNode {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<i64>,
}

fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && trimmed.chars().count() <= 64 && !trimmed.chars().any(char::is_control)
}

fn is_placeholder(host: &str) -> bool {
    host.trim()
        .get(..PLACEHOLDER_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(PLACEHOLDER_PREFIX))
}

/// A DNS hostname (at least two labels, ASCII letters/digits/hyphens) or a **public** IP literal.
pub fn valid_host(host: &str) -> bool {
    if let Ok(addr) = host.parse::<IpAddr>() {
        return is_public_ip(addr);
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false; // "localhost", "intranet": never a node
    }
    let label_ok = |label: &&str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    // The last label must not be all digits ("1.2.3.999" is not a hostname).
    labels.iter().all(label_ok) && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit())
}

/// Parse and validate `nodes.json`. Placeholder, duplicate and invalid entries are skipped and reported.
pub fn parse_nodes(data: &[u8]) -> Result<NodeList, NodesError> {
    if data.len() > MAX_NODES_BYTES {
        return Err(NodesError::TooLarge {
            limit: MAX_NODES_BYTES,
        });
    }
    let file: RawFile =
        serde_json::from_slice(data).map_err(|e| NodesError::Json(e.to_string()))?;
    if file.version != NODES_FORMAT_VERSION {
        return Err(NodesError::UnsupportedVersion {
            found: file.version,
        });
    }
    let mut list = NodeList::default();
    let mut seen = HashSet::new();
    for (index, raw) in file.nodes.into_iter().enumerate() {
        let mut skip = |reason| list.skipped.push(SkippedNode { index, reason });
        if list.nodes.len() >= MAX_NODES {
            skip(SkipReason::TooMany);
            continue;
        }
        let Some(id) = raw.id.filter(|id| valid_id(id)) else {
            skip(SkipReason::InvalidId);
            continue;
        };
        let Some(name) = raw.name.filter(|n| valid_name(n)) else {
            skip(SkipReason::InvalidName);
            continue;
        };
        let host = raw.host.unwrap_or_default().trim().to_owned();
        if is_placeholder(&host) {
            skip(SkipReason::Placeholder);
            continue;
        }
        if !valid_host(&host) {
            skip(SkipReason::InvalidHost);
            continue;
        }
        let Some(port) = raw
            .port
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
        else {
            skip(SkipReason::InvalidPort);
            continue;
        };
        if !seen.insert(id.clone()) {
            skip(SkipReason::DuplicateId);
            continue;
        }
        list.nodes.push(Node {
            id,
            name: name.trim().to_owned(),
            host,
            port,
        });
    }
    Ok(list)
}

/// Download and parse the node list from `url` (normally [`NODES_URL`]).
pub async fn fetch_nodes<F: Fetcher>(fetcher: &F, url: &str) -> Result<NodeList, NodesError> {
    let response = fetcher
        .fetch(FetchRequest::get(url, MAX_NODES_BYTES))
        .await?;
    if !response.is_success() {
        return Err(NodesError::HttpStatus(response.status));
    }
    parse_nodes(&response.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeFetcher;
    use crate::FetchResponse;

    #[test]
    fn the_repository_template_has_no_usable_nodes() {
        // docs/RELEASE-KEYS.md §3, as shipped.
        let json = r#"{
          "version": 1,
          "nodes": [
            { "id": "mia", "name": "Miami",     "host": "REPLACE-WITH-REAL-HOSTNAME", "port": 443 },
            { "id": "dal", "name": "Dallas",    "host": "REPLACE-WITH-REAL-HOSTNAME", "port": 443 },
            { "id": "sao", "name": "São Paulo", "host": "REPLACE-WITH-REAL-HOSTNAME", "port": 443 }
          ]
        }"#;
        let list = parse_nodes(json.as_bytes()).unwrap();
        assert!(list.is_empty());
        assert_eq!(list.skipped.len(), 3);
        assert!(list
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::Placeholder));
    }

    #[test]
    fn an_empty_list_is_valid() {
        assert!(parse_nodes(br#"{"version":1,"nodes":[]}"#)
            .unwrap()
            .is_empty());
        assert!(parse_nodes(br#"{"version":1}"#).unwrap().is_empty());
    }

    #[test]
    fn valid_nodes_are_kept_and_unknown_fields_ignored() {
        // Reserved example domains only: the real hostnames do not exist yet.
        let json = r#"{"version":1,"extra":true,"nodes":[
            {"id":"a-1","name":"Node A","host":"node-a.example.com","port":443,"region":"x"},
            {"id":"b","name":"Node B","host":"203.0.114.7","port":8443}
        ]}"#;
        let list = parse_nodes(json.as_bytes()).unwrap();
        assert_eq!(list.nodes.len(), 2);
        assert_eq!(list.nodes[0].host, "node-a.example.com");
        assert_eq!(list.nodes[1].port, 8443);
        assert!(list.skipped.is_empty());
    }

    #[test]
    fn bad_entries_are_skipped_individually() {
        let json = r#"{"version":1,"nodes":[
            {"id":"ok","name":"Fine","host":"ok.example.com","port":443},
            {"id":"BAD ID","name":"x","host":"a.example.com","port":443},
            {"id":"noname","name":"  ","host":"a.example.com","port":443},
            {"id":"p0","name":"Port zero","host":"a.example.com","port":0},
            {"id":"p70","name":"Port big","host":"a.example.com","port":70000},
            {"id":"pneg","name":"Port neg","host":"a.example.com","port":-1},
            {"id":"nop","name":"No port","host":"a.example.com"},
            {"id":"h1","name":"Localhost","host":"localhost","port":443},
            {"id":"h2","name":"Private","host":"10.0.0.5","port":443},
            {"id":"h3","name":"Loopback","host":"127.0.0.1","port":443},
            {"id":"h4","name":"Bad label","host":"-x.example.com","port":443},
            {"id":"h5","name":"Spaces","host":"a b.example.com","port":443},
            {"id":"h6","name":"Url","host":"https://a.example.com","port":443},
            {"id":"ok","name":"Duplicate","host":"dup.example.com","port":443},
            {"id":"h7","name":"Numeric tld","host":"1.2.3.999","port":443},
            {"id":"nohost","name":"No host","port":443}
        ]}"#;
        let list = parse_nodes(json.as_bytes()).unwrap();
        assert_eq!(list.nodes.len(), 1);
        assert_eq!(list.nodes[0].id, "ok");
        let reasons: Vec<SkipReason> = list.skipped.iter().map(|s| s.reason).collect();
        use SkipReason::*;
        assert_eq!(
            reasons,
            [
                InvalidId,
                InvalidName,
                InvalidPort,
                InvalidPort,
                InvalidPort,
                InvalidPort,
                InvalidHost,
                InvalidHost,
                InvalidHost,
                InvalidHost,
                InvalidHost,
                InvalidHost,
                DuplicateId,
                InvalidHost,
                InvalidHost
            ]
        );
    }

    #[test]
    fn file_level_problems_are_errors() {
        assert!(matches!(parse_nodes(b"not json"), Err(NodesError::Json(_))));
        assert!(matches!(parse_nodes(b"[]"), Err(NodesError::Json(_))));
        assert_eq!(
            parse_nodes(br#"{"version":2,"nodes":[]}"#).unwrap_err(),
            NodesError::UnsupportedVersion { found: 2 }
        );
        assert!(matches!(
            parse_nodes(br#"{"nodes":[]}"#),
            Err(NodesError::Json(_))
        ));
        let big = vec![b' '; MAX_NODES_BYTES + 1];
        assert!(matches!(
            parse_nodes(&big),
            Err(NodesError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_node_count_is_capped() {
        let mut entries = Vec::new();
        for n in 0..(MAX_NODES + 5) {
            entries.push(format!(
                r#"{{"id":"n{n}","name":"N {n}","host":"n{n}.example.com","port":443}}"#
            ));
        }
        let json = format!(r#"{{"version":1,"nodes":[{}]}}"#, entries.join(","));
        let list = parse_nodes(json.as_bytes()).unwrap();
        assert_eq!(list.nodes.len(), MAX_NODES);
        assert_eq!(list.skipped.len(), 5);
        assert!(list.skipped.iter().all(|s| s.reason == SkipReason::TooMany));
    }

    #[test]
    fn host_validation() {
        for ok in [
            "a.example.com",
            "xn--bcher-kva.example",
            "1-2.example.org",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "a.example.com.",
        ] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "a",
            "a..b.com",
            "-a.com",
            "a-.com",
            "a_b.com",
            "10.0.0.1",
            "::1",
            "fe80::1",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
        assert!(!valid_host(&format!("{}.com", "a".repeat(64))));
        assert!(!valid_host(&format!("{}.com", "a.".repeat(130))));
    }

    #[test]
    fn the_url_is_https_and_points_at_the_blocklist_repo() {
        assert!(NODES_URL.starts_with("https://"));
        assert!(NODES_URL.contains("XeroHost/packetward-blocklist"));
        assert!(NODES_URL.ends_with("/nodes.json"));
    }

    #[tokio::test]
    async fn fetching_goes_through_the_fetcher_with_a_size_cap() {
        let fetcher = FakeFetcher::new();
        fetcher.push(Ok(FetchResponse::ok(
            br#"{"version":1,"nodes":[]}"#.to_vec(),
        )));
        assert!(fetch_nodes(&fetcher, NODES_URL).await.unwrap().is_empty());
        assert_eq!(fetcher.requests()[0].url, NODES_URL);
        assert_eq!(fetcher.requests()[0].max_bytes, MAX_NODES_BYTES);

        fetcher.push(Ok(FetchResponse::ok("").with_status(404)));
        assert_eq!(
            fetch_nodes(&fetcher, NODES_URL).await.unwrap_err(),
            NodesError::HttpStatus(404)
        );
        fetcher.push(Err(FetchError::Timeout));
        assert!(matches!(
            fetch_nodes(&fetcher, NODES_URL).await,
            Err(NodesError::Fetch(FetchError::Timeout))
        ));
    }
}
