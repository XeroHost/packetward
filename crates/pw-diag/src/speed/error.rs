// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Errors of the speed-test client.
//!
//! Nothing here carries a URL, a query string, a proxy address or a credential: transport errors are reduced to a
//! short description by the transport itself, and server messages are truncated and stripped of control characters.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Which per-IP byte budget of the server a run would not fit in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetWindow {
    /// `limits.hourly_bytes_per_ip`.
    Hour,
    /// `limits.daily_bytes_per_ip`.
    Day,
}

impl std::fmt::Display for BudgetWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BudgetWindow::Hour => "hourly",
            BudgetWindow::Day => "daily",
        })
    }
}

/// A failure of one HTTP exchange, as reported by a [`SpeedTransport`](super::SpeedTransport).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportError {
    /// The exchange did not finish in time.
    #[error("timed out")]
    Timeout,
    /// The TCP/TLS connection could not be established.
    #[error("connection failed: {0}")]
    Connect(String),
    /// The connection broke or the body could not be read or written.
    #[error("transfer failed: {0}")]
    Io(String),
    /// The server answered with a non-success status.
    #[error("the server answered HTTP {status}")]
    Status {
        /// HTTP status code (400, 408, 413, 429, ...).
        status: u16,
        /// Seconds from the `Retry-After` header, when present and numeric.
        retry_after_secs: Option<u64>,
        /// The `message` of the server's JSON error body (truncated), when present.
        message: Option<String>,
    },
    /// The answer was not what the speed-server protocol defines.
    #[error("unexpected response: {0}")]
    Protocol(String),
}

/// Why a speed test did not produce a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpeedError {
    /// An option or a server address was rejected before anything was sent.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The caller cancelled (or the progress receiver went away). All traffic has stopped.
    #[error("the speed test was cancelled")]
    Cancelled,
    /// There is no usable server: the list is empty or no server answered.
    #[error("no speed-test server is available")]
    NoServer,
    /// The 50 GiB bin test needs `confirm_large: true` (bandwidth and time warning shown to the user first).
    #[error("a {size_bytes}-byte test moves a lot of data and needs an explicit confirmation")]
    ConfirmationRequired {
        /// Nominal size of the refused test.
        size_bytes: u64,
    },
    /// The server answered HTTP 429: stop and try later. The client does not retry.
    #[error("the server is rate limiting this client{}", retry_hint(.retry_after_secs))]
    RateLimited {
        /// The server's `Retry-After`, in seconds.
        retry_after_secs: Option<u64>,
    },
    /// The run cannot fit in the server's published per-IP byte budget, so it was not started.
    #[error(
        "the test needs {requested_bytes} bytes but the server's {window} budget is {limit_bytes} bytes \
         ({available_bytes} left by this client's own accounting)"
    )]
    BudgetExceeded {
        /// Which budget.
        window: BudgetWindow,
        /// Bytes the run would ask for.
        requested_bytes: u64,
        /// The published budget.
        limit_bytes: u64,
        /// `limit - what this client already used` in that window. The server's own remaining budget is not
        /// published, so this is an estimate.
        available_bytes: u64,
    },
    /// The server refused the request (HTTP 400, 408, 413 or another error status).
    #[error("the server refused the request (HTTP {status}){}", message_hint(.message))]
    Server {
        /// HTTP status.
        status: u16,
        /// Server-provided text, truncated.
        message: Option<String>,
    },
    /// A download stream ended before the requested number of bytes arrived.
    #[error("a stream ended early: expected {expected} bytes, got {received}")]
    Incomplete {
        /// Bytes requested.
        expected: u64,
        /// Bytes received.
        received: u64,
    },
    /// A network-level failure.
    #[error("network error: {cause}")]
    Transport {
        /// What went wrong.
        cause: TransportError,
    },
}

fn retry_hint(secs: &Option<u64>) -> String {
    secs.map_or_else(String::new, |s| format!(" (retry in {s} s)"))
}

fn message_hint(message: &Option<String>) -> String {
    message
        .as_deref()
        .map_or_else(String::new, |m| format!(": {m}"))
}

impl From<TransportError> for SpeedError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Status {
                status: 429,
                retry_after_secs,
                ..
            } => SpeedError::RateLimited { retry_after_secs },
            TransportError::Status {
                status, message, ..
            } => SpeedError::Server { status, message },
            cause => SpeedError::Transport { cause },
        }
    }
}

/// Make server-supplied text safe to show: no control characters, at most 200 characters.
#[cfg(any(feature = "speed", test))]
pub(crate) fn sanitize_message(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_429_becomes_rate_limited_with_the_retry_hint() {
        let error = SpeedError::from(TransportError::Status {
            status: 429,
            retry_after_secs: Some(17),
            message: Some("slow down".into()),
        });
        assert_eq!(
            error,
            SpeedError::RateLimited {
                retry_after_secs: Some(17)
            }
        );
        assert!(error.to_string().contains("retry in 17 s"));
    }

    #[test]
    fn other_statuses_and_network_errors_keep_their_shape() {
        let refused = SpeedError::from(TransportError::Status {
            status: 413,
            retry_after_secs: None,
            message: Some("too big".into()),
        });
        assert_eq!(
            refused,
            SpeedError::Server {
                status: 413,
                message: Some("too big".into())
            }
        );
        assert_eq!(
            SpeedError::from(TransportError::Timeout),
            SpeedError::Transport {
                cause: TransportError::Timeout
            }
        );
    }

    #[test]
    fn server_text_is_sanitized() {
        let dirty = format!("a\u{1b}[31mb\n{}", "x".repeat(500));
        let clean = sanitize_message(&dirty);
        assert!(!clean.contains('\u{1b}') && !clean.contains('\n'));
        assert_eq!(clean.chars().count(), 200);
    }

    #[test]
    fn errors_serialize_with_a_kind_tag() {
        let json = serde_json::to_string(&SpeedError::Cancelled).unwrap();
        assert_eq!(json, r#"{"kind":"cancelled"}"#);
        let back: SpeedError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SpeedError::Cancelled);
    }
}
