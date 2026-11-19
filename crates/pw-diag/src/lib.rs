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
pub mod mtr_adv;
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

#[cfg(test)]
mod send_sync_tests {
    //! Compile-time guarantees the engine relies on: the public types are `Send + Sync` and the
    //! futures of the public async entry points are `Send` (so they can be `tokio::spawn`ed),
    //! including the production reverse-DNS chain.
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    fn assert_send<T: Send>(_: &T) {}
    fn assert_send_sync<T: Send + Sync>() {}

    #[tokio::test]
    async fn public_api_is_send_and_sync() {
        assert_send_sync::<SystemPinger>();
        assert_send_sync::<DnsClient<HickoryBackend>>();
        assert_send_sync::<NameCache<DnsClient<HickoryBackend>>>();
        assert_send_sync::<PortCheckLimiter>();
        assert_send_sync::<CancelToken>();
        assert_send_sync::<PingOptions>();
        assert_send_sync::<MtrSnapshot>();
        assert_send_sync::<DnsLookup>();
        assert_send_sync::<PortCheck>();
        assert_send_sync::<DiagError>();

        let options = DnsOptions {
            resolver: ResolverChoice::Custom(vec!["127.0.0.1".parse().unwrap()]),
            timeout: Duration::from_secs(1),
        };
        let client = DnsClient::with_options(&options).unwrap();
        {
            let lookup = client.lookup("example.com", DnsRecordType::All);
            assert_send(&lookup);
        }
        let mtr_options = MtrOptions::default();
        let ping_options = PingOptions::default();

        let names = NameCache::new(Arc::new(client), Duration::from_secs(1));
        let cancel = CancelToken::new();
        let target: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        let (mut tx, _rx) = tokio::sync::mpsc::channel::<MtrSnapshot>(1);
        let trace = mtr(
            Arc::new(SystemPinger),
            target,
            &mtr_options,
            &names,
            &cancel,
            &mut tx,
        );
        assert_send(&trace);

        let (mut ptx, _prx) = tokio::sync::mpsc::channel::<PingReply>(1);
        let echo = ping(&SystemPinger, target, &ping_options, &cancel, &mut ptx);
        assert_send(&echo);

        let connect = tcp_connect("127.0.0.1", 80, Duration::from_secs(1));
        assert_send(&connect);
        let probe = udp_check("127.0.0.1", 53, Duration::from_secs(1));
        assert_send(&probe);
        let limited = PortCheckLimiter::default();
        let limited_connect = limited.tcp_connect("127.0.0.1", 80, Duration::from_secs(1));
        assert_send(&limited_connect);
    }
}
