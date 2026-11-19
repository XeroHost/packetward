// SPDX-License-Identifier: GPL-3.0-or-later
//! MTR (advanced): ICMP, UDP and TCP-SYN probe modes, IPv4 and IPv6, ASN + country per hop and
//! plain-text / CSV / JSON export.
//!
//! The cycle engine is the one behind [`crate::mtr()`]; this module generalises *how a probe is
//! sent and its answer read*:
//!
//! * [`ProbeTransport`] sends one probe with a given TTL and reports what came back. The ICMP
//!   implementation is [`PingerTransport`] (any [`crate::Pinger`], so the Win32 ICMP helper API
//!   needs neither raw sockets nor administrator rights). UDP and TCP-SYN probes cannot read
//!   their answers (ICMP time-exceeded, port-unreachable, SYN-ACK, RST) through ordinary sockets,
//!   so [`CaptureProbeTransport`] reads them from a `pw_capture::PacketSource`; when no capture
//!   backend is available the mode reports [`ModeUnavailable`] instead of failing obscurely.
//! * [`FakeProbeTransport`] scripts hop sequences for tests.
//! * [`HopEnricher`] + [`EnrichCache`] add ASN / country per hop from a *local* database. Private
//!   and reserved addresses are never handed to the enricher.
//! * [`mtr_with`] runs a trace and streams [`AdvMtrSnapshot`]s; [`export`] renders them as the
//!   support report, CSV or JSON.
//!
//! Every limit of the simple MTR (cycles, hops, timeout, interval, parallelism) is shared, so a
//! typo cannot turn the tool into a flood: see [`AdvMtrOptions::normalized_for`].

pub mod capture;
mod engine;
pub mod enrich;
pub mod export;
pub mod fake;
mod options;
mod snapshot;
pub(crate) mod sys;
pub mod wire;

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

use crate::echo::{EchoReply, EchoRequest, EchoStatus, Pinger};
use crate::error::DiagError;

pub use capture::{
    BoundProbe, CaptureProbeTransport, ProbeSender, SentProbe, SystemProbeTransport,
    MAX_PENDING_PROBES,
};
pub use engine::mtr_with;
pub use enrich::{is_public_ip, EnrichCache, HopEnricher, HopInfo, NoEnrich};
pub use fake::FakeProbeTransport;
pub use options::{
    AdvMtrOptions, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT, MAX_PAYLOAD_V6, TCP_SYN_PAYLOAD,
};
pub use snapshot::{AdvHop, AdvMtrSnapshot};

/// Which kind of packet each probe is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProbeMode {
    /// ICMP / ICMPv6 echo request (works everywhere, no capture backend needed).
    #[default]
    Icmp,
    /// Classic traceroute: a UDP datagram to a high port. A hop answers ICMP time-exceeded; the
    /// destination answers ICMP port-unreachable.
    Udp,
    /// A TCP SYN to `port`. A hop answers ICMP time-exceeded; the destination answers SYN-ACK
    /// (port open) or RST (port closed). Reaches hosts that drop ICMP and UDP.
    TcpSyn {
        /// Destination port, `1..=65535` (0 is refused).
        port: u16,
    },
}

impl ProbeMode {
    /// Short label for tables and reports: `ICMP`, `UDP` or `TCP SYN`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Icmp => "ICMP",
            Self::Udp => "UDP",
            Self::TcpSyn { .. } => "TCP SYN",
        }
    }

    /// `true` for the modes that need to read raw replies (everything except ICMP echo).
    pub fn needs_capture(self) -> bool {
        !matches!(self, Self::Icmp)
    }
}

impl fmt::Display for ProbeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// How the destination answered (why the trace ended).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReachKind {
    /// ICMP / ICMPv6 echo reply.
    EchoReply,
    /// ICMP port-unreachable from the destination (UDP mode: the normal "arrived" signal).
    PortUnreachable,
    /// TCP SYN-ACK: the port is open.
    SynAck,
    /// TCP RST: the host is up, the port is closed.
    Rst,
}

impl ReachKind {
    /// Lower-case label used by the exports.
    pub fn label(self) -> &'static str {
        match self {
            Self::EchoReply => "echo-reply",
            Self::PortUnreachable => "port-unreachable",
            Self::SynAck => "syn-ack",
            Self::Rst => "rst",
        }
    }
}

/// What one probe found out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// A router answered "TTL / hop limit exceeded".
    TtlExpired,
    /// The destination answered.
    Reached(ReachKind),
    /// Somebody answered "unreachable" (any code other than the destination's port-unreachable).
    Unreachable,
    /// Nothing usable came back within the timeout.
    TimedOut,
}

/// The answer to one [`ProbeRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReply {
    /// Outcome.
    pub status: ProbeStatus,
    /// Who answered.
    pub from: Option<IpAddr>,
    /// Round-trip time; `None` when nothing came back.
    pub rtt: Option<Duration>,
}

impl ProbeReply {
    /// A router at `from` said the TTL ran out.
    pub fn ttl_expired(from: IpAddr, rtt: Duration) -> Self {
        Self {
            status: ProbeStatus::TtlExpired,
            from: Some(from),
            rtt: Some(rtt),
        }
    }

    /// The destination answered with `kind`.
    pub fn reached(kind: ReachKind, from: IpAddr, rtt: Duration) -> Self {
        Self {
            status: ProbeStatus::Reached(kind),
            from: Some(from),
            rtt: Some(rtt),
        }
    }

    /// Somebody at `from` said "unreachable".
    pub fn unreachable(from: IpAddr, rtt: Duration) -> Self {
        Self {
            status: ProbeStatus::Unreachable,
            from: Some(from),
            rtt: Some(rtt),
        }
    }

    /// Nothing came back.
    pub fn timed_out() -> Self {
        Self {
            status: ProbeStatus::TimedOut,
            from: None,
            rtt: None,
        }
    }

    /// The same outcome in the vocabulary of the ICMP engine: any destination answer is
    /// `Success`.
    pub(crate) fn to_echo(&self) -> EchoReply {
        EchoReply {
            status: match self.status {
                ProbeStatus::TtlExpired => EchoStatus::TtlExpired,
                ProbeStatus::Reached(_) => EchoStatus::Success,
                ProbeStatus::Unreachable => EchoStatus::Unreachable,
                ProbeStatus::TimedOut => EchoStatus::TimedOut,
            },
            from: self.from,
            rtt: self.rtt,
            ttl: None,
        }
    }
}

/// One probe to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    /// The destination of the trace.
    pub target: IpAddr,
    /// Probe kind.
    pub mode: ProbeMode,
    /// TTL (IPv4) or hop limit (IPv6), `1..=255`.
    pub ttl: u8,
    /// Payload bytes (ICMP echo data or UDP datagram body; a TCP SYN carries none).
    pub payload_size: u16,
    /// Destination port (UDP and TCP; `0` for ICMP).
    pub port: u16,
    /// How long to wait for the answer.
    pub timeout: Duration,
    /// Running probe number within the trace (for tracing and fakes).
    pub seq: u32,
}

/// A probe mode that cannot run here, and why. Reported *before* anything is sent when possible.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{mode} probes are unavailable: {reason}")]
pub struct ModeUnavailable {
    /// The mode that was requested.
    pub mode: ProbeMode,
    /// Human readable explanation, including what to do about it.
    pub reason: String,
}

impl ModeUnavailable {
    /// Build the error.
    pub fn new(mode: ProbeMode, reason: impl Into<String>) -> Self {
        Self {
            mode,
            reason: reason.into(),
        }
    }
}

/// Why an advanced MTR could not run (as opposed to a result such as "destination not reached").
#[derive(Debug, Error)]
pub enum MtrError {
    /// The mode cannot run on this machine / with this transport.
    #[error(transparent)]
    ModeUnavailable(#[from] ModeUnavailable),
    /// Something refused or failed: bad option, nothing could be sent, ...
    #[error(transparent)]
    Diag(#[from] DiagError),
}

/// Sends one probe and reads its answer. Implementations are shared (`&self`) because MTR runs
/// several probes concurrently.
pub trait ProbeTransport: Send + Sync {
    /// Called once before a trace: can this transport run `mode` towards `target`? May allocate
    /// resources (open the capture interface). The default accepts everything.
    fn prepare(&self, _mode: ProbeMode, _target: IpAddr) -> Result<(), ModeUnavailable> {
        Ok(())
    }

    /// Send `request` and wait at most `request.timeout`. A timeout is a normal
    /// [`ProbeStatus::TimedOut`] reply; `Err` means the probe could not even be sent.
    fn probe(
        &self,
        request: &ProbeRequest,
    ) -> impl Future<Output = Result<ProbeReply, MtrError>> + Send;
}

/// [`ProbeTransport`] for ICMP echo over any [`Pinger`] (IPv4 and IPv6). UDP and TCP-SYN are
/// reported as [`ModeUnavailable`]: an echo API cannot read their answers.
#[derive(Debug)]
pub struct PingerTransport<P> {
    pinger: Arc<P>,
}

impl<P> PingerTransport<P> {
    /// Wrap `pinger`.
    pub fn new(pinger: Arc<P>) -> Self {
        Self { pinger }
    }
}

impl<P: Pinger + 'static> ProbeTransport for PingerTransport<P> {
    fn prepare(&self, mode: ProbeMode, _target: IpAddr) -> Result<(), ModeUnavailable> {
        match mode {
            ProbeMode::Icmp => Ok(()),
            other => Err(ModeUnavailable::new(
                other,
                "this transport only sends ICMP echo; UDP and TCP probes need a capture backend \
                 (Npcap or the raw-socket backend) to read their replies",
            )),
        }
    }

    async fn probe(&self, request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        self.prepare(request.mode, request.target)?;
        let reply = self
            .pinger
            .echo(&EchoRequest {
                target: request.target,
                ttl: request.ttl,
                payload_size: request.payload_size,
                timeout: request.timeout,
            })
            .await?;
        let status = match reply.status {
            EchoStatus::Success => ProbeStatus::Reached(ReachKind::EchoReply),
            EchoStatus::TtlExpired => ProbeStatus::TtlExpired,
            EchoStatus::Unreachable => ProbeStatus::Unreachable,
            EchoStatus::TimedOut | EchoStatus::Other(_) => ProbeStatus::TimedOut,
        };
        Ok(ProbeReply {
            status,
            from: reply.from,
            rtt: reply.rtt,
        })
    }
}
