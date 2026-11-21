// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Ping (IPv4 and IPv6) on top of a [`Pinger`].

use std::net::IpAddr;
use std::time::Duration;

use tokio::time::Instant;

use crate::cancel::CancelToken;
use crate::echo::{
    clamp_timeout, EchoReply, EchoRequest, EchoStatus, Pinger, DEFAULT_PAYLOAD, DEFAULT_TTL,
    MAX_PAYLOAD,
};
use crate::error::DiagError;
use crate::sink::Sink;
use crate::stats::{loss_percent, RttStats, RttSummary};

/// Most echoes one ping run may send. Pings are a diagnostic, not a load generator.
pub const MAX_COUNT: u32 = 1000;
/// Shortest allowed gap between two echoes of the same run.
pub const MIN_INTERVAL: Duration = Duration::from_millis(200);

/// Ping parameters. Out-of-range values are clamped, see [`PingOptions::normalized`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingOptions {
    /// Number of echoes, `1..=`[`MAX_COUNT`] (default 4).
    pub count: u32,
    /// Per-echo timeout (default 2 s, at most 10 s).
    pub timeout: Duration,
    /// Echo payload size in bytes (default 32, at most [`MAX_PAYLOAD`]).
    pub packet_size: u16,
    /// TTL / hop limit (default 128).
    pub ttl: u8,
    /// Time between the *starts* of two echoes (default 1 s, at least [`MIN_INTERVAL`]).
    pub interval: Duration,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            count: 4,
            timeout: Duration::from_secs(2),
            packet_size: DEFAULT_PAYLOAD,
            ttl: DEFAULT_TTL,
            interval: Duration::from_secs(1),
        }
    }
}

impl PingOptions {
    /// The options with every field forced into its supported range.
    pub fn normalized(&self) -> PingOptions {
        PingOptions {
            count: self.count.clamp(1, MAX_COUNT),
            timeout: clamp_timeout(self.timeout),
            packet_size: self.packet_size.min(MAX_PAYLOAD),
            ttl: self.ttl.max(1),
            interval: self.interval.max(MIN_INTERVAL),
        }
    }
}

/// One echo and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingReply {
    /// 0-based echo number within the run.
    pub seq: u32,
    /// What came back.
    pub status: EchoStatus,
    /// Who answered.
    pub from: Option<IpAddr>,
    /// Round-trip time (monotonic clock, sub-millisecond on loopback).
    pub rtt: Option<Duration>,
    /// TTL of the reply; `None` for IPv6 (the API does not report it) and for non-replies.
    pub ttl: Option<u8>,
    /// Payload bytes sent.
    pub bytes: u16,
    /// Set when the probe could not be sent at all (the message of the underlying error).
    pub error: Option<String>,
}

/// The totals of a ping run.
#[derive(Debug, Clone, PartialEq)]
pub struct PingSummary {
    /// The destination pinged.
    pub target: IpAddr,
    /// Echoes sent.
    pub sent: u32,
    /// Echo replies received (only [`EchoStatus::Success`] counts).
    pub received: u32,
    /// `(sent - received) / sent * 100`.
    pub loss_percent: f64,
    /// Round-trip statistics over the received echoes; `None` when nothing was received.
    pub rtt: Option<RttSummary>,
    /// True when the run ended early because of cancellation or a vanished consumer.
    pub cancelled: bool,
}

/// Ping `target`, delivering every [`PingReply`] to `sink` as it happens, and return the summary.
///
/// Cancelling `cancel` (or dropping the receiving end of a channel sink) stops the run after the
/// echo in flight; the summary covers what was sent so far and has `cancelled == true`.
pub async fn ping<P, S>(
    pinger: &P,
    target: IpAddr,
    options: &PingOptions,
    cancel: &CancelToken,
    sink: &mut S,
) -> PingSummary
where
    P: Pinger,
    S: Sink<PingReply>,
{
    let opts = options.normalized();
    let request = EchoRequest {
        target,
        ttl: opts.ttl,
        payload_size: opts.packet_size,
        timeout: opts.timeout,
    };
    let mut stats = RttStats::new();
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut cancelled = false;

    for seq in 0..opts.count {
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
        let started = Instant::now();
        let outcome = tokio::select! {
            r = pinger.echo(&request) => Some(r),
            () = cancel.cancelled() => None,
        };
        let Some(outcome) = outcome else {
            cancelled = true;
            break;
        };
        sent += 1;
        let reply = to_ping_reply(seq, opts.packet_size, outcome);
        if reply.status == EchoStatus::Success {
            received += 1;
            if let Some(rtt) = reply.rtt {
                stats.add(rtt);
            }
        }
        let delivered = tokio::select! {
            ok = sink.deliver(reply) => ok,
            () = cancel.cancelled() => false,
        };
        if !delivered {
            cancelled = true;
            break;
        }
        if seq + 1 < opts.count {
            tokio::select! {
                () = tokio::time::sleep_until(started + opts.interval) => {}
                () = cancel.cancelled() => { cancelled = true; break; }
            }
        }
    }

    PingSummary {
        target,
        sent,
        received,
        loss_percent: loss_percent(u64::from(sent), u64::from(received)),
        rtt: stats.summary(),
        cancelled,
    }
}

fn to_ping_reply(seq: u32, bytes: u16, outcome: Result<EchoReply, DiagError>) -> PingReply {
    match outcome {
        Ok(r) => PingReply {
            seq,
            status: r.status,
            from: r.from,
            rtt: r.rtt,
            ttl: r.ttl,
            bytes,
            error: None,
        },
        Err(e) => PingReply {
            seq,
            status: EchoStatus::TimedOut,
            from: None,
            rtt: None,
            ttl: None,
            bytes,
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakePinger;
    use crate::sink::{FnSink, NullSink};
    use tokio::sync::mpsc;

    fn target() -> IpAddr {
        "192.0.2.10".parse().unwrap()
    }

    fn ok(ms: u64) -> Result<EchoReply, DiagError> {
        Ok(EchoReply {
            status: EchoStatus::Success,
            from: Some(target()),
            rtt: Some(Duration::from_millis(ms)),
            ttl: Some(57),
        })
    }

    #[tokio::test(start_paused = true)]
    async fn summary_counts_loss_and_stats() {
        // replies: 10, lost, 30, 20
        let pinger = FakePinger::new(|_, n| match n {
            1 => Ok(EchoReply::timed_out()),
            0 => ok(10),
            2 => ok(30),
            _ => ok(20),
        });
        let mut got = Vec::new();
        let mut sink = FnSink(|r: PingReply| got.push(r));
        let cancel = CancelToken::new();
        let s = ping(
            &pinger,
            target(),
            &PingOptions::default(),
            &cancel,
            &mut sink,
        )
        .await;
        assert_eq!((s.sent, s.received), (4, 3));
        assert!((s.loss_percent - 25.0).abs() < 1e-9);
        let rtt = s.rtt.unwrap();
        assert!((rtt.min_ms - 10.0).abs() < 1e-9);
        assert!((rtt.avg_ms - 20.0).abs() < 1e-9);
        assert!((rtt.max_ms - 30.0).abs() < 1e-9);
        assert!((rtt.stddev_ms - 10.0).abs() < 1e-9);
        assert!(!s.cancelled);
        assert_eq!(got.len(), 4);
        assert_eq!(got[1].status, EchoStatus::TimedOut);
        assert_eq!(got[0].ttl, Some(57));
        assert_eq!(got[3].seq, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn options_are_clamped_and_forwarded() {
        let pinger = FakePinger::new(|_, _| ok(1));
        let opts = PingOptions {
            count: 1,
            timeout: Duration::from_secs(99),
            packet_size: 60_000,
            ttl: 0,
            interval: Duration::ZERO,
        };
        let cancel = CancelToken::new();
        ping(&pinger, target(), &opts, &cancel, &mut NullSink).await;
        let req = &pinger.requests()[0];
        assert_eq!(req.timeout, Duration::from_secs(10));
        assert_eq!(req.payload_size, MAX_PAYLOAD);
        assert_eq!(req.ttl, 1);
        let big = PingOptions {
            count: 1_000_000,
            ..PingOptions::default()
        };
        assert_eq!(big.normalized().count, MAX_COUNT);
        assert_eq!(opts.normalized().interval, MIN_INTERVAL);
    }

    #[tokio::test(start_paused = true)]
    async fn default_options_match_ping_exe() {
        let o = PingOptions::default();
        assert_eq!((o.count, o.packet_size, o.ttl), (4, 32, 128));
    }

    #[tokio::test(start_paused = true)]
    async fn interval_paces_echoes() {
        let pinger = FakePinger::new(|_, _| ok(1));
        let cancel = CancelToken::new();
        let t0 = Instant::now();
        ping(
            &pinger,
            target(),
            &PingOptions::default(),
            &cancel,
            &mut NullSink,
        )
        .await;
        // 4 echoes, 1 s between starts, no wait after the last one.
        assert_eq!(t0.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_during_wait_stops_run() {
        let pinger = FakePinger::new(|_, _| ok(1));
        let cancel = CancelToken::new();
        let c2 = cancel.clone();
        let mut sink = FnSink(move |r: PingReply| {
            if r.seq == 1 {
                c2.cancel();
            }
        });
        let s = ping(
            &pinger,
            target(),
            &PingOptions::default(),
            &cancel,
            &mut sink,
        )
        .await;
        assert!(s.cancelled);
        assert_eq!(s.sent, 2);
        assert_eq!(pinger.requests().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_interrupts_probe_in_flight() {
        let pinger = FakePinger::new(|_, _| ok(1)).with_delay(Duration::from_secs(5));
        let cancel = CancelToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c2.cancel();
        });
        let t0 = Instant::now();
        let s = ping(
            &pinger,
            target(),
            &PingOptions::default(),
            &cancel,
            &mut NullSink,
        )
        .await;
        assert!(s.cancelled);
        assert_eq!(s.sent, 0);
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn already_cancelled_sends_nothing() {
        let pinger = FakePinger::new(|_, _| ok(1));
        let cancel = CancelToken::new();
        cancel.cancel();
        let s = ping(
            &pinger,
            target(),
            &PingOptions::default(),
            &cancel,
            &mut NullSink,
        )
        .await;
        assert!(s.cancelled && s.sent == 0 && s.rtt.is_none());
        assert!(pinger.requests().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_receiver_counts_as_cancel() {
        let pinger = FakePinger::new(|_, _| ok(1));
        let (mut tx, rx) = mpsc::channel::<PingReply>(1);
        drop(rx);
        let cancel = CancelToken::new();
        let s = ping(&pinger, target(), &PingOptions::default(), &cancel, &mut tx).await;
        assert!(s.cancelled);
        assert_eq!(s.sent, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn channel_sink_streams_replies() {
        let pinger = FakePinger::new(|_, _| ok(2));
        let (mut tx, mut rx) = mpsc::channel::<PingReply>(2);
        let cancel = CancelToken::new();
        let opts = PingOptions {
            count: 3,
            ..PingOptions::default()
        };
        let consumer = tokio::spawn(async move {
            let mut n = 0;
            while rx.recv().await.is_some() {
                n += 1;
            }
            n
        });
        let s = ping(&pinger, target(), &opts, &cancel, &mut tx).await;
        drop(tx);
        assert_eq!(consumer.await.unwrap(), 3);
        assert_eq!(s.received, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn send_failure_is_reported_per_reply() {
        let pinger = FakePinger::new(|_, _| Err(DiagError::Unsupported("icmp")));
        let mut got = Vec::new();
        let mut sink = FnSink(|r: PingReply| got.push(r));
        let opts = PingOptions {
            count: 2,
            ..PingOptions::default()
        };
        let cancel = CancelToken::new();
        let s = ping(&pinger, target(), &opts, &cancel, &mut sink).await;
        assert_eq!((s.sent, s.received), (2, 0));
        assert!((s.loss_percent - 100.0).abs() < 1e-9);
        assert!(got[0].error.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn non_success_replies_do_not_count_as_received() {
        let pinger = FakePinger::new(|_, _| {
            Ok(EchoReply {
                status: EchoStatus::Unreachable,
                from: Some("192.0.2.1".parse().unwrap()),
                rtt: Some(Duration::from_millis(3)),
                ttl: Some(64),
            })
        });
        let opts = PingOptions {
            count: 2,
            ..PingOptions::default()
        };
        let cancel = CancelToken::new();
        let s = ping(&pinger, target(), &opts, &cancel, &mut NullSink).await;
        assert_eq!(s.received, 0);
        assert!(s.rtt.is_none());
    }
}
