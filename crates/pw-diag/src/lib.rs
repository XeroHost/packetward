// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-diag — ping, MTR, DNS lookup and remote port checks (the speed-test client is a later
//! milestone).
//!
//! Everything here is a *diagnostic for the machine's own owner*: single targets, capped counts,
//! capped timeouts. There is no scanning, no flooding and no telemetry.
//!
//! # Layout
//!
//! | Feature | Entry point | Platform part |
//! |---|---|---|
//! | Ping (IPv4/IPv6) | [`ping()`] | [`Pinger`] trait, Win32 ICMP helper API in `sys/windows.rs` ([`SystemPinger`]) |
//! | MTR (simple) | [`mtr()`], [`HopStats`], [`format_report`] | same [`Pinger`], plus [`ReverseLookup`] for host names |
//! | DNS lookup | [`DnsClient::lookup`] | [`DnsBackend`] trait; [`HickoryBackend`] is the real one |
//! | Port check | [`tcp_connect`], [`udp_check`], [`PortCheckLimiter`] | tokio sockets |
//!
//! Only the thin Win32 layer is platform specific. On other platforms [`SystemPinger`] fails with
//! [`DiagError::Unsupported`]; the logic is tested against [`fake::FakePinger`] and
//! [`fake::FakeDnsBackend`].
//!
//! # Conventions
//!
//! * **Everything that waits is `async`** and runs on tokio. The ICMP API is synchronous, so each
//!   probe uses the blocking pool; probe timeouts bound how long that thread is busy.
//! * **Streaming.** [`ping()`] delivers every reply and [`mtr()`] one table per cycle to a
//!   [`Sink`]: a bounded `tokio::sync::mpsc::Sender` (back-pressure, never an unbounded queue),
//!   a closure via [`FnSink`], or [`NullSink`] when only the final result matters. A sink whose
//!   receiver is gone counts as a cancellation.
//! * **Cancellation.** Pass a [`CancelToken`]; calling [`CancelToken::cancel`] from any clone
//!   interrupts the wait promptly. The summary/snapshot returned afterwards covers what completed
//!   and is flagged `cancelled`.
//! * **Guardrails are clamps, not errors.** Out-of-range options (count, timeout, packet size,
//!   TTL, interval, hops) are forced into their supported range by the `normalized()` methods.
//!   Only requests that must never be sent (port 0, empty host) return an error.
//! * **Public types are plain Rust** (no `ts-rs`, no hickory types): IPC types belong to
//!   `pw-proto` and are mapped from these by the engine. Durations are `Duration` on raw replies
//!   and `f64` milliseconds in statistics.
//! * **Clock resolution.** The Windows API reports round-trip times in whole milliseconds, so the
//!   probe is timed with a monotonic clock around the call instead; on loopback that gives
//!   microseconds rather than a flat `0 ms`.
//!
//! # Example
//!
//! ```no_run
//! # async fn demo() {
//! use pw_diag::{ping, CancelToken, FnSink, PingOptions, SystemPinger};
//!
//! let cancel = CancelToken::new();
//! let mut sink = FnSink(|reply: pw_diag::PingReply| println!("{reply:?}"));
//! let summary = ping(
//!     &SystemPinger,
//!     "1.1.1.1".parse().unwrap(),
//!     &PingOptions::default(),
//!     &cancel,
//!     &mut sink,
//! )
//! .await;
//! println!("{:.0}% loss", summary.loss_percent);
//! # }
//! ```

pub mod cancel;
pub mod dns;
mod dns_hickory;
pub mod echo;
pub mod error;
pub mod fake;
pub mod mtr;
pub mod names;
pub mod ping;
pub mod port;
pub mod report;
pub mod sink;
pub mod stats;
mod sys;

pub use cancel::CancelToken;
pub use dns::{
    DnsBackend, DnsClient, DnsFailure, DnsLookup, DnsOptions, DnsRecord, DnsRecordData,
    DnsRecordType, ResolverChoice,
};
pub use dns_hickory::HickoryBackend;
pub use echo::{EchoReply, EchoRequest, EchoStatus, Pinger};
pub use error::DiagError;
pub use mtr::{mtr, HopSnapshot, HopStats, MtrOptions, MtrSnapshot};
pub use names::{NameCache, NoReverse, ReverseLookup};
pub use ping::{ping, PingOptions, PingReply, PingSummary};
pub use port::{tcp_connect, udp_check, PortCheck, PortCheckLimiter, PortProtocol, PortState};
pub use report::{format_report, format_utc, ReportContext};
pub use sink::{FnSink, NullSink, Sink};
pub use stats::{RttStats, RttSummary};
pub use sys::SystemPinger;
