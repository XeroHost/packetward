// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-netstat — TCP/UDP tables with PID, adapters, interface counters, RDP sessions.
//!
//! The pure parts (table parsing, rate maths, aggregation, interface classification) are
//! platform-agnostic and tested on Linux. The Win32 backend lives in `sys/windows.rs`; the engine
//! only sees the [`NetStat`] trait, and tests use [`fake::FakeNetStat`].

pub mod aggregate;
pub mod classify;
pub mod fake;
pub mod logon;
pub mod rates;
pub mod rdp;
mod sys;
pub mod tables;

use std::collections::BTreeMap;
use std::io;

use std::sync::Arc;

use logon::LogonEvent;
use pw_proto::{Connection, LogonAudit, RdpSession, TrustFeed};

pub use classify::{classify_kind, counts_toward_total};
pub use rates::{Counters, RateTracker, Rates};
#[cfg(windows)]
pub use sys::windows::WindowsNetStat;

/// The RDP port unless the machine is configured otherwise.
pub const DEFAULT_RDP_PORT: u16 = 3389;

/// IF_TYPE values used by the classifier (IANA ifType).
pub mod if_type {
    pub const ETHERNET: u32 = 6;
    pub const LOOPBACK: u32 = 24;
    pub const IEEE80211: u32 = 71;
    pub const TUNNEL: u32 = 131;
}

/// One network interface as the operating system reports it, before any filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSample {
    pub index: u32,
    pub name: String,
    pub description: String,
    /// IANA ifType, see [`if_type`].
    pub if_type: u32,
    pub oper_up: bool,
    /// `HardwareInterface` flag: a physical or paravirtual NIC with a driver, not a software layer.
    pub hardware: bool,
    /// `FilterInterface` flag: a filter-driver layer on top of another interface (it would double
    /// count that interface's traffic).
    pub filter: bool,
    pub connector_present: bool,
    /// The interface carries a default route (IPv4 or IPv6).
    pub has_default_gateway: bool,
    pub link_speed_bps: u64,
    pub counters: Counters,
}

/// The connection table plus the names of the processes that own the rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionTable {
    pub rows: Vec<Connection>,
    /// One entry per distinct PID that could be resolved.
    pub processes: BTreeMap<u32, String>,
}

/// Source of network state. Implementations block, so callers run them off the async runtime.
/// Receives each successful RDP logon the event log feed learns about (from any thread).
pub type LogonSink = Arc<dyn Fn(LogonEvent) + Send + Sync>;

pub trait NetStat: Send + Sync + 'static {
    /// The "Audit Logon" policy. Without success events no RDP logon can be learned; without failure
    /// events RDP brute force cannot be detected.
    fn logon_audit(&self) -> LogonAudit {
        LogonAudit::default()
    }

    /// Starts learning successful RDP logons: subscribes to new events and loads recent history within
    /// a fixed budget (`window_ms` back). Blocks until that initial load is done. Returns whether the
    /// event log could be used; the feed stays alive for as long as the source does.
    fn start_logon_feed(&self, _window_ms: u64, _sink: LogonSink) -> TrustFeed {
        TrustFeed::Unavailable
    }

    /// The TCP port of the RDP listener.
    fn rdp_port(&self) -> u16 {
        DEFAULT_RDP_PORT
    }
    fn connections(&self) -> io::Result<ConnectionTable>;
    fn interfaces(&self) -> io::Result<Vec<InterfaceSample>>;
    fn rdp_sessions(&self) -> io::Result<Vec<RdpSession>>;
}
