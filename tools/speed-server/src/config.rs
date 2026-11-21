// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Configuration: TOML file, `PW_SPEED_*` environment overrides, CLI overrides, validation.
//!
//! Precedence (lowest to highest): built-in defaults < TOML file < environment < command line.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ip::{Cidr, ProxyPolicy};

const GIB: u64 = 1024 * 1024 * 1024;

/// A fully commented default configuration, printed by `--print-default-config`.
/// A unit test asserts that it parses to exactly [`Config::default`].
pub const DEFAULT_CONFIG_TOML: &str = r#"# pw-speed-server configuration (TOML).
# Precedence: defaults < this file < PW_SPEED_* environment variables < command-line flags.
# Byte sizes are in bytes; 1 GiB = 1073741824. For every limit marked "0 = unlimited", 0 disables that limit.

[node]
# Stable machine id (a-z, 0-9, '-', '_'); must match the "id" in nodes.json.
id = "local"
# Human readable name and location shown in /info and in the PacketWard UI.
name = "Local speed node"
location = ""

[server]
# Plain HTTP by default (local testing). In production put this behind a TLS reverse proxy or set [tls].
listen = "127.0.0.1:8080"
# Max time to receive the request headers of a connection.
header_read_timeout_secs = 10
# A connection that moves no bytes in either direction for this long is closed (idle keep-alive,
# stalled readers/writers).
idle_timeout_secs = 30
# Hard cap on the duration of a single download/upload (50 GiB at 100 Mbit/s takes ~72 minutes).
max_transfer_secs = 14400
# Max simultaneously open connections (bounded memory). Excess connections wait in the kernel backlog.
max_connections = 2048
# Max open connections per client IP (0 = unlimited). Not applied to trusted reverse proxies.
max_connections_per_ip = 128
# On SIGTERM/Ctrl-C, in-flight transfers get this long to finish before being cut.
shutdown_grace_secs = 10

# Optional native TLS (requires a binary built with `--features tls`). Both files or neither.
# [tls]
# cert_file = "/etc/pw-speed-server/fullchain.pem"
# key_file = "/etc/pw-speed-server/privkey.pem"

[limits]
# Largest GET /download?bytes=N accepted (50 GiB).
max_download_bytes = 53687091200
# Largest POST /upload body accepted (10 GiB).
max_upload_bytes = 10737418240
# A "test" is a group of parallel streams from one client IP (PacketWard tags its streams with the same
# ?test=<id>; a stream without an id counts as its own test).
max_concurrent_tests_per_ip = 2
# Streams (requests) allowed inside one test.
max_streams_per_test = 8
# Simultaneous tests on the whole server (0 = unlimited).
max_concurrent_tests_global = 64
# Request rate per client IP, token bucket (0 = unlimited).
requests_per_minute_per_ip = 600
# Bytes a single client IP may transfer per hour / per day (0 = unlimited). When not 0 they must be at
# least max_download_bytes so a full-size test can always pass.
hourly_bytes_per_ip = 107374182400
daily_bytes_per_ip = 322122547200

[proxy]
# Honor a client-IP header set by a reverse proxy. Only used when the TCP peer is in trusted_peers.
# Leave disabled when the server is exposed directly (a spoofed header would let clients evade limits).
trust_header = false
header = "X-Forwarded-For"
trusted_peers = ["127.0.0.0/8", "::1/128"]

[logging]
# tracing filter: "info", "debug", "pw_speed_server=debug,info", ...
level = "info"
# "text" or "json"
format = "text"
# Client IPs are truncated in logs (IPv4 /24, IPv6 /48) unless this is true.
log_full_ips = false
"#;

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("cannot read config file {path}: {source}")]
    Read {
        /// Path that failed.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The config file is not valid TOML / has unknown keys.
    #[error("invalid config file: {0}")]
    Parse(#[from] toml::de::Error),
    /// An environment override could not be parsed.
    #[error("invalid value for environment variable {var}: {message}")]
    Env {
        /// Variable name.
        var: String,
        /// What was wrong.
        message: String,
    },
    /// A semantic validation failure.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

/// Identity of this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    /// Stable id, matches nodes.json.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Free-form location (city, country).
    pub location: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: "local".into(),
            name: "Local speed node".into(),
            location: String::new(),
        }
    }
}

/// Listener and connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Header read timeout, seconds.
    pub header_read_timeout_secs: u64,
    /// Idle / stall timeout, seconds.
    pub idle_timeout_secs: u64,
    /// Hard cap on one transfer, seconds.
    pub max_transfer_secs: u64,
    /// Max open connections.
    pub max_connections: usize,
    /// Max open connections per client IP (0 = unlimited).
    pub max_connections_per_ip: usize,
    /// Graceful shutdown window, seconds.
    pub shutdown_grace_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            header_read_timeout_secs: 10,
            idle_timeout_secs: 30,
            max_transfer_secs: 4 * 3600,
            max_connections: 2048,
            max_connections_per_ip: 128,
            shutdown_grace_secs: 10,
        }
    }
}

/// Optional native TLS.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert_file: Option<PathBuf>,
    /// PEM private key.
    pub key_file: Option<PathBuf>,
}

impl TlsConfig {
    /// True when TLS is configured.
    pub fn enabled(&self) -> bool {
        self.cert_file.is_some() && self.key_file.is_some()
    }
}

/// Protection limits. `0` means unlimited unless stated otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Max `bytes` for /download (must be > 0).
    pub max_download_bytes: u64,
    /// Max body for /upload (must be > 0).
    pub max_upload_bytes: u64,
    /// Concurrent tests per client IP.
    pub max_concurrent_tests_per_ip: usize,
    /// Streams per test (must be > 0).
    pub max_streams_per_test: usize,
    /// Concurrent tests server-wide.
    pub max_concurrent_tests_global: usize,
    /// Requests per minute per client IP.
    pub requests_per_minute_per_ip: u64,
    /// Bytes per hour per client IP.
    pub hourly_bytes_per_ip: u64,
    /// Bytes per day per client IP.
    pub daily_bytes_per_ip: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_download_bytes: 50 * GIB,
            max_upload_bytes: 10 * GIB,
            max_concurrent_tests_per_ip: 2,
            max_streams_per_test: 8,
            max_concurrent_tests_global: 64,
            requests_per_minute_per_ip: 600,
            hourly_bytes_per_ip: 100 * GIB,
            daily_bytes_per_ip: 300 * GIB,
        }
    }
}

/// Reverse-proxy client-IP header handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Honor `header` (only from `trusted_peers`).
    pub trust_header: bool,
    /// Header carrying the client IP.
    pub header: String,
    /// CIDRs of reverse proxies allowed to set the header.
    pub trusted_peers: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            trust_header: false,
            header: "X-Forwarded-For".into(),
            trusted_peers: vec!["127.0.0.0/8".into(), "::1/128".into()],
        }
    }
}

/// Logging settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing` filter directive.
    pub level: String,
    /// `text` or `json`.
    pub format: String,
    /// Log complete client IPs instead of truncated ones.
    pub log_full_ips: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "text".into(),
            log_full_ips: false,
        }
    }
}

/// The complete configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Node identity.
    pub node: NodeConfig,
    /// Listener settings.
    pub server: ServerConfig,
    /// Native TLS.
    pub tls: TlsConfig,
    /// Protection limits.
    pub limits: LimitsConfig,
    /// Proxy header handling.
    pub proxy: ProxyConfig,
    /// Logging.
    pub logging: LoggingConfig,
}

/// Command-line overrides (applied last).
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// `--listen`
    pub listen: Option<SocketAddr>,
    /// `--node-id`
    pub node_id: Option<String>,
    /// `--node-name`
    pub node_name: Option<String>,
    /// `--location`
    pub location: Option<String>,
    /// `--log-level`
    pub log_level: Option<String>,
}

impl Config {
    /// Parse a TOML document (no env, no validation).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(text)?)
    }

    /// Read and parse a TOML file (no env, no validation).
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Apply `PW_SPEED_*` overrides read through `get` (the real environment in production).
    pub fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) -> Result<(), ConfigError> {
        fn parse<T: FromStr>(var: &str, raw: &str) -> Result<T, ConfigError>
        where
            T::Err: std::fmt::Display,
        {
            raw.trim().parse::<T>().map_err(|e| ConfigError::Env {
                var: var.to_string(),
                message: e.to_string(),
            })
        }
        fn parse_bool(var: &str, raw: &str) -> Result<bool, ConfigError> {
            match raw.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Ok(true),
                "0" | "false" | "no" | "off" => Ok(false),
                _ => Err(ConfigError::Env {
                    var: var.to_string(),
                    message: "expected true/false".into(),
                }),
            }
        }
        macro_rules! set {
            ($var:literal, $field:expr, $conv:expr) => {
                if let Some(raw) = get($var) {
                    $field = $conv($var, &raw)?;
                }
            };
        }
        let text =
            |_: &str, raw: &str| -> Result<String, ConfigError> { Ok(raw.trim().to_string()) };
        let path = |_: &str, raw: &str| -> Result<Option<PathBuf>, ConfigError> {
            let raw = raw.trim();
            Ok(if raw.is_empty() {
                None
            } else {
                Some(PathBuf::from(raw))
            })
        };
        let list = |_: &str, raw: &str| -> Result<Vec<String>, ConfigError> {
            Ok(raw
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect())
        };

        set!("PW_SPEED_LISTEN", self.server.listen, parse::<SocketAddr>);
        set!(
            "PW_SPEED_HEADER_READ_TIMEOUT_SECS",
            self.server.header_read_timeout_secs,
            parse::<u64>
        );
        set!(
            "PW_SPEED_IDLE_TIMEOUT_SECS",
            self.server.idle_timeout_secs,
            parse::<u64>
        );
        set!(
            "PW_SPEED_MAX_TRANSFER_SECS",
            self.server.max_transfer_secs,
            parse::<u64>
        );
        set!(
            "PW_SPEED_MAX_CONNECTIONS",
            self.server.max_connections,
            parse::<usize>
        );
        set!(
            "PW_SPEED_MAX_CONNECTIONS_PER_IP",
            self.server.max_connections_per_ip,
            parse::<usize>
        );
        set!(
            "PW_SPEED_SHUTDOWN_GRACE_SECS",
            self.server.shutdown_grace_secs,
            parse::<u64>
        );

        set!("PW_SPEED_NODE_ID", self.node.id, text);
        set!("PW_SPEED_NODE_NAME", self.node.name, text);
        set!("PW_SPEED_NODE_LOCATION", self.node.location, text);

        set!("PW_SPEED_TLS_CERT_FILE", self.tls.cert_file, path);
        set!("PW_SPEED_TLS_KEY_FILE", self.tls.key_file, path);

        set!(
            "PW_SPEED_MAX_DOWNLOAD_BYTES",
            self.limits.max_download_bytes,
            parse::<u64>
        );
        set!(
            "PW_SPEED_MAX_UPLOAD_BYTES",
            self.limits.max_upload_bytes,
            parse::<u64>
        );
        set!(
            "PW_SPEED_MAX_TESTS_PER_IP",
            self.limits.max_concurrent_tests_per_ip,
            parse::<usize>
        );
        set!(
            "PW_SPEED_MAX_STREAMS_PER_TEST",
            self.limits.max_streams_per_test,
            parse::<usize>
        );
        set!(
            "PW_SPEED_MAX_TESTS_GLOBAL",
            self.limits.max_concurrent_tests_global,
            parse::<usize>
        );
        set!(
            "PW_SPEED_REQUESTS_PER_MINUTE",
            self.limits.requests_per_minute_per_ip,
            parse::<u64>
        );
        set!(
            "PW_SPEED_HOURLY_BYTES_PER_IP",
            self.limits.hourly_bytes_per_ip,
            parse::<u64>
        );
        set!(
            "PW_SPEED_DAILY_BYTES_PER_IP",
            self.limits.daily_bytes_per_ip,
            parse::<u64>
        );

        set!(
            "PW_SPEED_PROXY_TRUST_HEADER",
            self.proxy.trust_header,
            parse_bool
        );
        set!("PW_SPEED_PROXY_HEADER", self.proxy.header, text);
        set!(
            "PW_SPEED_PROXY_TRUSTED_PEERS",
            self.proxy.trusted_peers,
            list
        );

        set!("PW_SPEED_LOG_LEVEL", self.logging.level, text);
        set!("PW_SPEED_LOG_FORMAT", self.logging.format, text);
        set!(
            "PW_SPEED_LOG_FULL_IPS",
            self.logging.log_full_ips,
            parse_bool
        );
        Ok(())
    }

    /// Apply command-line overrides.
    pub fn apply_overrides(&mut self, o: &Overrides) {
        if let Some(v) = o.listen {
            self.server.listen = v;
        }
        if let Some(v) = &o.node_id {
            self.node.id = v.clone();
        }
        if let Some(v) = &o.node_name {
            self.node.name = v.clone();
        }
        if let Some(v) = &o.location {
            self.node.location = v.clone();
        }
        if let Some(v) = &o.log_level {
            self.logging.level = v.clone();
        }
    }

    /// Check cross-field constraints. Call after all overrides are applied.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let id = &self.node.id;
        if id.is_empty()
            || id.len() > 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(invalid(
                "node.id must be 1-32 chars of a-z, 0-9, '-' or '_'",
            ));
        }
        if self.node.name.trim().is_empty() || self.node.name.len() > 64 {
            return Err(invalid("node.name must be 1-64 characters"));
        }
        if self.node.location.len() > 64 {
            return Err(invalid("node.location must be at most 64 characters"));
        }
        let s = &self.server;
        if s.header_read_timeout_secs == 0 || s.idle_timeout_secs == 0 || s.max_transfer_secs == 0 {
            return Err(invalid(
                "server.header_read_timeout_secs, idle_timeout_secs and max_transfer_secs must be > 0",
            ));
        }
        if s.max_connections == 0 {
            return Err(invalid("server.max_connections must be > 0"));
        }
        if self.tls.cert_file.is_some() != self.tls.key_file.is_some() {
            return Err(invalid(
                "tls.cert_file and tls.key_file must be set together",
            ));
        }
        let l = &self.limits;
        if l.max_download_bytes == 0 || l.max_upload_bytes == 0 {
            return Err(invalid(
                "limits.max_download_bytes and max_upload_bytes must be > 0",
            ));
        }
        if l.max_download_bytes > i64::MAX as u64 || l.max_upload_bytes > i64::MAX as u64 {
            return Err(invalid(
                "limits.max_*_bytes must fit in a signed 64-bit integer",
            ));
        }
        if l.max_streams_per_test == 0 {
            return Err(invalid("limits.max_streams_per_test must be > 0"));
        }
        for (name, v) in [
            ("hourly_bytes_per_ip", l.hourly_bytes_per_ip),
            ("daily_bytes_per_ip", l.daily_bytes_per_ip),
        ] {
            if v != 0 && v < l.max_download_bytes {
                return Err(invalid(format!(
                    "limits.{name} ({v}) is smaller than limits.max_download_bytes ({}): the largest test could never run",
                    l.max_download_bytes
                )));
            }
        }
        if l.hourly_bytes_per_ip != 0
            && l.daily_bytes_per_ip != 0
            && l.hourly_bytes_per_ip > l.daily_bytes_per_ip
        {
            return Err(invalid(
                "limits.hourly_bytes_per_ip must not exceed daily_bytes_per_ip",
            ));
        }
        self.proxy_policy()?;
        match self.logging.format.as_str() {
            "text" | "json" => {}
            other => {
                return Err(invalid(format!(
                    "logging.format must be \"text\" or \"json\", got {other:?}"
                )))
            }
        }
        Ok(())
    }

    /// Build the proxy policy (parses the header name and the CIDR list).
    pub fn proxy_policy(&self) -> Result<ProxyPolicy, ConfigError> {
        let header = axum::http::HeaderName::from_str(&self.proxy.header)
            .map_err(|e| invalid(format!("proxy.header: {e}")))?;
        let mut trusted = Vec::new();
        for raw in &self.proxy.trusted_peers {
            trusted.push(
                Cidr::from_str(raw)
                    .map_err(|e| invalid(format!("proxy.trusted_peers {raw:?}: {e}")))?,
            );
        }
        Ok(ProxyPolicy {
            enabled: self.proxy.trust_header,
            header,
            trusted,
        })
    }

    /// Header read timeout as a `Duration`.
    pub fn header_read_timeout(&self) -> Duration {
        Duration::from_secs(self.server.header_read_timeout_secs)
    }

    /// Idle timeout as a `Duration`.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.server.idle_timeout_secs)
    }

    /// Max transfer duration as a `Duration`.
    pub fn max_transfer(&self) -> Duration {
        Duration::from_secs(self.server.max_transfer_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_toml_matches_default_config_and_validates() {
        let parsed = Config::from_toml(DEFAULT_CONFIG_TOML).unwrap();
        assert_eq!(parsed, Config::default());
        parsed.validate().unwrap();
    }

    #[test]
    fn partial_file_keeps_defaults() {
        let c = Config::from_toml(
            "[node]\nid = \"mia\"\nname = \"Miami\"\n[limits]\nmax_download_bytes = 1000\n",
        )
        .unwrap();
        assert_eq!(c.node.id, "mia");
        assert_eq!(c.limits.max_download_bytes, 1000);
        assert_eq!(
            c.limits.max_upload_bytes,
            LimitsConfig::default().max_upload_bytes
        );
        assert_eq!(c.server, ServerConfig::default());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::from_toml("[limits]\nmax_download_byts = 5\n").is_err());
        assert!(Config::from_toml("bogus = 1\n").is_err());
    }

    #[test]
    fn env_overrides_file_and_cli_overrides_env() {
        let mut c = Config::from_toml("[node]\nname = \"File\"\n").unwrap();
        let env = |k: &str| match k {
            "PW_SPEED_NODE_NAME" => Some("Env".to_string()),
            "PW_SPEED_LISTEN" => Some("0.0.0.0:9000".to_string()),
            "PW_SPEED_MAX_TESTS_PER_IP" => Some("5".to_string()),
            "PW_SPEED_PROXY_TRUST_HEADER" => Some("true".to_string()),
            "PW_SPEED_PROXY_TRUSTED_PEERS" => Some("10.0.0.0/8, 192.168.0.0/16".to_string()),
            _ => None,
        };
        c.apply_env(&env).unwrap();
        assert_eq!(c.node.name, "Env");
        assert_eq!(c.server.listen, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(c.limits.max_concurrent_tests_per_ip, 5);
        assert!(c.proxy.trust_header);
        assert_eq!(c.proxy.trusted_peers, vec!["10.0.0.0/8", "192.168.0.0/16"]);
        c.apply_overrides(&Overrides {
            node_name: Some("Cli".into()),
            ..Overrides::default()
        });
        assert_eq!(c.node.name, "Cli");
        assert_eq!(c.server.listen, "0.0.0.0:9000".parse().unwrap());
    }

    #[test]
    fn bad_env_values_name_the_variable() {
        let mut c = Config::default();
        let err = c
            .apply_env(&|k| (k == "PW_SPEED_MAX_UPLOAD_BYTES").then(|| "lots".to_string()))
            .unwrap_err();
        assert!(
            err.to_string().contains("PW_SPEED_MAX_UPLOAD_BYTES"),
            "{err}"
        );
        let err = c
            .apply_env(&|k| (k == "PW_SPEED_PROXY_TRUST_HEADER").then(|| "maybe".to_string()))
            .unwrap_err();
        assert!(
            err.to_string().contains("PW_SPEED_PROXY_TRUST_HEADER"),
            "{err}"
        );
    }

    fn assert_invalid(mutate: impl FnOnce(&mut Config), needle: &str) {
        let mut c = Config::default();
        mutate(&mut c);
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains(needle), "{err:?} should contain {needle:?}");
    }

    #[test]
    fn validation_rejects_bad_values() {
        assert_invalid(|c| c.node.id = "Bad Id".into(), "node.id");
        assert_invalid(|c| c.node.id.clear(), "node.id");
        assert_invalid(|c| c.node.name = " ".into(), "node.name");
        assert_invalid(|c| c.server.idle_timeout_secs = 0, "must be > 0");
        assert_invalid(|c| c.server.max_connections = 0, "max_connections");
        assert_invalid(
            |c| c.tls.cert_file = Some("cert.pem".into()),
            "set together",
        );
        assert_invalid(|c| c.limits.max_download_bytes = 0, "max_download_bytes");
        assert_invalid(
            |c| c.limits.max_streams_per_test = 0,
            "max_streams_per_test",
        );
        assert_invalid(|c| c.limits.hourly_bytes_per_ip = 1024, "could never run");
        assert_invalid(
            |c| {
                c.limits.hourly_bytes_per_ip = 200 * GIB;
                c.limits.daily_bytes_per_ip = 100 * GIB;
            },
            "hourly_bytes_per_ip must not exceed",
        );
        assert_invalid(|c| c.proxy.header = "bad header".into(), "proxy.header");
        assert_invalid(
            |c| c.proxy.trusted_peers = vec!["not-a-cidr".into()],
            "trusted_peers",
        );
        assert_invalid(|c| c.logging.format = "xml".into(), "logging.format");
    }

    #[test]
    fn zero_means_unlimited_and_validates() {
        let mut c = Config::default();
        c.limits.hourly_bytes_per_ip = 0;
        c.limits.daily_bytes_per_ip = 0;
        c.limits.requests_per_minute_per_ip = 0;
        c.limits.max_concurrent_tests_per_ip = 0;
        c.limits.max_concurrent_tests_global = 0;
        c.server.max_connections_per_ip = 0;
        c.validate().unwrap();
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let err = Config::from_file(Path::new("/definitely/not/here.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
