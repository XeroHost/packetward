// SPDX-License-Identifier: GPL-3.0-or-later
//! The two traits every capture backend implements, and the plain types they exchange.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::CaptureError;
use crate::filter::Filter;

/// Default number of bytes kept per packet: headers only (docs/DECISIONS.md, "Captures").
pub const DEFAULT_SNAPLEN: u32 = 128;
/// Default time a source blocks waiting for a packet before returning [`SourceEvent::Timeout`].
/// It bounds how long stopping a capture can take.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_millis(250);

/// Identifies what to capture on. Accepted spellings (resolved by the backend with the interface list):
/// an adapter GUID (`{...}`), an Npcap device name (`\Device\NPF_{...}`), the adapter's friendly name,
/// or one of its IP addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InterfaceId(pub String);

impl InterfaceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendKind {
    Npcap,
    RawSocket,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Npcap => "Npcap",
            Self::RawSocket => "Windows raw socket",
        }
    }
}

/// What a frame returned by a source starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkType {
    /// Ethernet II (optionally VLAN tagged).
    Ethernet,
    /// An IPv4 or IPv6 packet with no link header (raw sockets, DLT_RAW).
    RawIp,
    /// BSD loopback: a 4-byte address-family word, then the IP packet (the Npcap loopback adapter).
    Null,
}

impl LinkType {
    /// Maps a libpcap `DLT_*` value; `None` for link types this crate cannot decode.
    pub fn from_dlt(dlt: i32) -> Option<Self> {
        match dlt {
            0 => Some(Self::Null),
            1 => Some(Self::Ethernet),
            // DLT_RAW differs per OS (12 on Windows and Linux, 14 on OpenBSD); 101 is LINKTYPE_RAW and
            // 228/229 are the IPv4-only / IPv6-only variants.
            12 | 14 | 101 | 228 | 229 => Some(Self::RawIp),
            _ => None,
        }
    }
}

/// One captured frame. The data borrows the source's own buffer and is valid until the next read.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// Nanoseconds since the Unix epoch (capture clock).
    pub timestamp_ns: u64,
    /// The captured bytes (at most the snap length).
    pub data: &'a [u8],
    /// Length of the frame on the wire; at least `data.len()`.
    pub original_len: u32,
}

#[derive(Debug)]
pub enum SourceEvent<'a> {
    Frame(Frame<'a>),
    /// The read timed out with nothing to report; the caller may check its stop flag and call again.
    Timeout,
    /// The source is exhausted (a finite replay). Live sources never return this.
    Eof,
}

/// A stream of frames from one interface. Reading blocks for at most the configured read timeout.
/// Dropping the source closes it.
pub trait PacketSource: Send {
    fn link_type(&self) -> LinkType;

    /// Addresses of the interface, used to tell inbound from outbound packets.
    fn local_addrs(&self) -> &[IpAddr];

    /// Waits up to the read timeout for the next frame. Must not allocate per packet.
    fn next(&mut self) -> Result<SourceEvent<'_>, CaptureError>;

    /// Packets the operating system or driver dropped before this process saw them, when known.
    fn kernel_drops(&self) -> u64 {
        0
    }
}

/// Options for opening a source.
#[derive(Debug, Clone)]
pub struct CaptureOpts {
    /// Bytes kept per packet. Default [`DEFAULT_SNAPLEN`].
    pub snaplen: u32,
    /// Put the adapter in promiscuous mode. Off by default (this tool watches the host's own traffic).
    pub promiscuous: bool,
    /// Longest blocking wait of [`PacketSource::next`].
    pub read_timeout: Duration,
    /// Optional pre-filter. Backends with BPF translate it to a kernel filter to save work; the
    /// pipeline and the recorder always apply it again in Rust, so ignoring it is always correct.
    pub filter: Option<Filter>,
    /// Kernel buffer size in bytes (`0` = backend default).
    pub buffer_bytes: u32,
}

impl Default for CaptureOpts {
    fn default() -> Self {
        Self {
            snaplen: DEFAULT_SNAPLEN,
            promiscuous: false,
            read_timeout: DEFAULT_READ_TIMEOUT,
            filter: None,
            buffer_bytes: 0,
        }
    }
}

impl CaptureOpts {
    /// Checks the values before a backend acts on them.
    pub fn validate(&self) -> Result<(), CaptureError> {
        if !(64..=262_144).contains(&self.snaplen) {
            return Err(CaptureError::InvalidSettings(format!(
                "snaplen {} is outside 64..=262144",
                self.snaplen
            )));
        }
        if self.read_timeout.is_zero() || self.read_timeout > Duration::from_secs(10) {
            return Err(CaptureError::InvalidSettings(
                "read timeout must be between 1 ms and 10 s".into(),
            ));
        }
        Ok(())
    }
}

/// What a backend can do, for the UI to explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCaps {
    pub kind: BackendKind,
    /// Frames include the Ethernet header (otherwise the IP packet starts at byte 0).
    pub link_layer: bool,
    /// Filters can be pushed down to the kernel as BPF.
    pub bpf: bool,
    /// Sees packets this host sends as well as the ones it receives.
    pub sees_outbound: bool,
    pub ipv6: bool,
    pub needs_admin: bool,
}

pub trait CaptureBackend: Send + Sync {
    fn caps(&self) -> BackendCaps;

    fn open(
        &self,
        interface: &InterfaceId,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError>;
}
