// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! One ICMP echo probe: the [`Pinger`] trait plus the platform-neutral request/reply types.
//!
//! The Windows implementation (`IcmpSendEcho2Ex` / `Icmp6SendEcho2`) lives in `sys/windows.rs`;
//! ping and MTR are written against the trait so they run on fakes in tests.

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use crate::error::DiagError;

/// Longest probe timeout accepted anywhere in this crate.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(10);
/// Shortest probe timeout (the ICMP API takes whole milliseconds).
pub const MIN_TIMEOUT: Duration = Duration::from_millis(1);
/// Largest echo payload. Conservative: roughly one Ethernet frame, so a typo cannot turn the
/// tool into a fragment generator.
pub const MAX_PAYLOAD: u16 = 1472;
/// Default echo payload, the same as `ping.exe`.
pub const DEFAULT_PAYLOAD: u16 = 32;
/// Default TTL / hop limit for a plain ping, the same as Windows.
pub const DEFAULT_TTL: u8 = 128;

/// What one probe found out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoStatus {
    /// The destination answered (echo reply).
    Success,
    /// An intermediate router answered "TTL / hop limit exceeded" (what MTR is looking for).
    TtlExpired,
    /// Somebody answered "destination unreachable" (any code).
    Unreachable,
    /// Nothing came back within the timeout.
    TimedOut,
    /// The stack reported another ICMP-helper status; the raw `IP_STATUS` code is kept.
    Other(u32),
}

/// One echo request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoRequest {
    /// Where to send it.
    pub target: IpAddr,
    /// TTL (IPv4) or hop limit (IPv6), `1..=255`.
    pub ttl: u8,
    /// Payload bytes, `0..=`[`MAX_PAYLOAD`].
    pub payload_size: u16,
    /// How long to wait for an answer, `1 ms..=`[`MAX_TIMEOUT`].
    pub timeout: Duration,
}

impl EchoRequest {
    /// The request with every field forced into the supported range.
    pub fn clamped(&self) -> EchoRequest {
        EchoRequest {
            target: self.target,
            ttl: self.ttl.max(1),
            payload_size: self.payload_size.min(MAX_PAYLOAD),
            timeout: clamp_timeout(self.timeout),
        }
    }
}

/// The answer to one [`EchoRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    /// Outcome.
    pub status: EchoStatus,
    /// Who answered (the target, or the router that sent TTL exceeded / unreachable).
    pub from: Option<IpAddr>,
    /// Round-trip time; `None` when nothing came back.
    pub rtt: Option<Duration>,
    /// TTL of the reply packet. The ICMPv6 API does not report it, so this is `None` there.
    pub ttl: Option<u8>,
}

impl EchoReply {
    /// A reply meaning "nothing came back".
    pub fn timed_out() -> Self {
        Self {
            status: EchoStatus::TimedOut,
            from: None,
            rtt: None,
            ttl: None,
        }
    }
}

/// Sends one ICMP echo and waits for the outcome. Implementations must be cheap to share
/// (`&self`) because MTR runs several probes concurrently.
pub trait Pinger: Send + Sync {
    /// Send `request` (already clamped by the callers) and wait at most `request.timeout`.
    ///
    /// A timeout is a normal [`EchoStatus::TimedOut`] reply, not an error. `Err` is reserved for
    /// "could not even send" (no ICMP handle, no route to the address family, ...).
    fn echo(
        &self,
        request: &EchoRequest,
    ) -> impl Future<Output = Result<EchoReply, DiagError>> + Send;
}

/// Force a timeout into `MIN_TIMEOUT..=MAX_TIMEOUT`.
pub fn clamp_timeout(timeout: Duration) -> Duration {
    timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

/// Raw `IP_STATUS` values of the ICMP helper API. Defined here (not taken from the `windows`
/// crate) so the mapping below is testable on every platform.
pub mod ip_status {
    /// `IP_SUCCESS`
    pub const SUCCESS: u32 = 0;
    /// `IP_BUF_TOO_SMALL`
    pub const BUF_TOO_SMALL: u32 = 11001;
    /// `IP_DEST_NET_UNREACHABLE` (also `IP_DEST_NO_ROUTE` for IPv6)
    pub const DEST_NET_UNREACHABLE: u32 = 11002;
    /// `IP_DEST_HOST_UNREACHABLE`
    pub const DEST_HOST_UNREACHABLE: u32 = 11003;
    /// `IP_DEST_PROT_UNREACHABLE` (also `IP_DEST_PROHIBITED`)
    pub const DEST_PROT_UNREACHABLE: u32 = 11004;
    /// `IP_DEST_PORT_UNREACHABLE`
    pub const DEST_PORT_UNREACHABLE: u32 = 11005;
    /// `IP_REQ_TIMED_OUT`
    pub const REQ_TIMED_OUT: u32 = 11010;
    /// `IP_TTL_EXPIRED_TRANSIT` (`IP_HOP_LIMIT_EXCEEDED` for IPv6)
    pub const TTL_EXPIRED_TRANSIT: u32 = 11013;
    /// `IP_TTL_EXPIRED_REASSEM`
    pub const TTL_EXPIRED_REASSEM: u32 = 11014;
    /// `IP_DEST_SCOPE_MISMATCH`
    pub const DEST_SCOPE_MISMATCH: u32 = 11045;
}

/// Map a raw `IP_STATUS` to an [`EchoStatus`].
pub fn status_from_code(code: u32) -> EchoStatus {
    use ip_status::*;
    match code {
        SUCCESS => EchoStatus::Success,
        TTL_EXPIRED_TRANSIT | TTL_EXPIRED_REASSEM => EchoStatus::TtlExpired,
        REQ_TIMED_OUT => EchoStatus::TimedOut,
        DEST_NET_UNREACHABLE
        | DEST_HOST_UNREACHABLE
        | DEST_PROT_UNREACHABLE
        | DEST_PORT_UNREACHABLE
        | DEST_SCOPE_MISMATCH => EchoStatus::Unreachable,
        other => EchoStatus::Other(other),
    }
}

/// Size of the reply buffer the ICMP helper needs: the reply structure, the echoed payload, room
/// for an ICMP error message (8 bytes) and an `IO_STATUS_BLOCK`. A little extra slack is added
/// because Windows rejects buffers that are exactly at the documented minimum on some builds.
pub fn reply_buffer_len(reply_struct: usize, payload: usize, io_status_block: usize) -> usize {
    reply_struct
        .saturating_add(payload)
        .saturating_add(8)
        .saturating_add(io_status_block)
        .saturating_add(64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_status_codes() {
        assert_eq!(status_from_code(0), EchoStatus::Success);
        assert_eq!(status_from_code(11013), EchoStatus::TtlExpired);
        assert_eq!(status_from_code(11014), EchoStatus::TtlExpired);
        assert_eq!(status_from_code(11010), EchoStatus::TimedOut);
        for code in [11002, 11003, 11004, 11005, 11045] {
            assert_eq!(status_from_code(code), EchoStatus::Unreachable, "{code}");
        }
        assert_eq!(status_from_code(11050), EchoStatus::Other(11050));
        assert_eq!(status_from_code(11001), EchoStatus::Other(11001));
    }

    #[test]
    fn clamps_request_fields() {
        let wild = EchoRequest {
            target: "127.0.0.1".parse().unwrap(),
            ttl: 0,
            payload_size: u16::MAX,
            timeout: Duration::from_secs(3600),
        };
        let c = wild.clamped();
        assert_eq!(c.ttl, 1);
        assert_eq!(c.payload_size, MAX_PAYLOAD);
        assert_eq!(c.timeout, MAX_TIMEOUT);
        let zero = EchoRequest {
            timeout: Duration::ZERO,
            ..wild
        };
        assert_eq!(zero.clamped().timeout, MIN_TIMEOUT);
    }

    #[test]
    fn reply_buffer_covers_documented_minimum() {
        // Documented minimum: reply struct + payload + 8 + IO_STATUS_BLOCK.
        let len = reply_buffer_len(28, 32, 16);
        assert!(len >= 28 + 32 + 8 + 16);
        assert_eq!(reply_buffer_len(usize::MAX, 1, 1), usize::MAX);
    }
}
