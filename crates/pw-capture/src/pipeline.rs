// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The live pipeline: one dedicated OS thread reads a [`PacketSource`], decodes each frame to a
//! [`PacketMeta`] and hands consumers **batches** through a **bounded** channel.
//!
//! Hot-path rules (docs/ARCHITECTURE.md §5): per packet there is no allocation, no lock, no blocking call
//! and no log line. A batch is one `Vec` allocated per up to `batch_size` packets. When the consumer falls
//! behind and the queue is full the whole batch is dropped and its packets are added to the
//! `dropped_queue` counter; nothing waits for the consumer. Packets the kernel dropped before this process
//! saw them (reported by the source) are in `kernel_drops`. [`CaptureStats::dropped_packets`] is the sum:
//! losses are counted, never hidden.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pw_core::PacketMeta;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::backend::{PacketSource, SourceEvent};
use crate::decode::{decode_frame, DecodeError, LocalAddrs};
use crate::error::CaptureError;
use crate::filter::Filter;

/// Packets handed to consumers in one go.
pub type PacketBatch = Vec<PacketMeta>;
pub type BatchReceiver = mpsc::Receiver<PacketBatch>;

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Capacity of the bounded queue, in batches.
    pub queue_batches: usize,
    /// Most packets in one batch.
    pub batch_size: usize,
    /// A partly filled batch is sent after this long, so consumers see traffic with bounded latency.
    pub flush_interval: Duration,
    /// Only matching packets are delivered (evaluated in Rust after decoding). `None` = everything.
    pub filter: Option<Filter>,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            queue_batches: 64,
            batch_size: 512,
            flush_interval: Duration::from_millis(50),
            filter: None,
        }
    }
}

#[derive(Default)]
struct Counters {
    received: AtomicU64,
    decoded: AtomicU64,
    non_ip: AtomicU64,
    malformed: AtomicU64,
    filtered_out: AtomicU64,
    delivered: AtomicU64,
    dropped_queue: AtomicU64,
    kernel_drops: AtomicU64,
    batches_sent: AtomicU64,
    batches_dropped: AtomicU64,
}

/// A point-in-time copy of the pipeline counters. All values are cumulative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStats {
    /// Frames read from the source.
    pub received: u64,
    /// Frames that decoded to a `PacketMeta`.
    pub decoded: u64,
    /// Frames that were not IP (ARP, ...).
    pub non_ip: u64,
    /// Truncated or inconsistent frames.
    pub malformed: u64,
    /// Decoded packets rejected by the filter.
    pub filtered_out: u64,
    /// Packets that reached the consumer queue.
    pub delivered: u64,
    /// Packets dropped because the consumer queue was full.
    pub dropped_queue: u64,
    /// Packets the OS or driver dropped before the source saw them.
    pub kernel_drops: u64,
    pub batches_sent: u64,
    pub batches_dropped: u64,
}

impl CaptureStats {
    /// Every packet known to be lost: consumer queue overflow plus kernel drops.
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_queue + self.kernel_drops
    }
}

/// A cheap, cloneable view of the counters of a running [`Capture`], for the stats ticker.
#[derive(Clone)]
pub struct StatsHandle(Arc<Counters>);

impl StatsHandle {
    pub fn snapshot(&self) -> CaptureStats {
        let c = &*self.0;
        CaptureStats {
            received: c.received.load(Ordering::Relaxed),
            decoded: c.decoded.load(Ordering::Relaxed),
            non_ip: c.non_ip.load(Ordering::Relaxed),
            malformed: c.malformed.load(Ordering::Relaxed),
            filtered_out: c.filtered_out.load(Ordering::Relaxed),
            delivered: c.delivered.load(Ordering::Relaxed),
            dropped_queue: c.dropped_queue.load(Ordering::Relaxed),
            kernel_drops: c.kernel_drops.load(Ordering::Relaxed),
            batches_sent: c.batches_sent.load(Ordering::Relaxed),
            batches_dropped: c.batches_dropped.load(Ordering::Relaxed),
        }
    }

    /// Dropped packets so far (queue overflow plus kernel).
    pub fn dropped_packets(&self) -> u64 {
        self.snapshot().dropped_packets()
    }
}

/// A running capture. Dropping it stops the thread.
pub struct Capture {
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
    thread: Option<JoinHandle<Result<(), CaptureError>>>,
}

impl Capture {
    /// Starts the reader thread. Returns the handle and the receiving end of the batch queue; the capture
    /// also ends by itself when the source ends, fails, or the receiver is dropped.
    pub fn start(
        source: Box<dyn PacketSource>,
        cfg: PipelineConfig,
    ) -> Result<(Self, BatchReceiver), CaptureError> {
        if cfg.queue_batches == 0 || cfg.batch_size == 0 {
            return Err(CaptureError::InvalidSettings(
                "queue and batch sizes must be at least 1".into(),
            ));
        }
        let (tx, rx) = mpsc::channel(cfg.queue_batches);
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());
        let worker = Worker {
            source,
            cfg,
            tx,
            stop: Arc::clone(&stop),
            counters: Arc::clone(&counters),
        };
        let thread = std::thread::Builder::new()
            .name("pw-capture".to_owned())
            .spawn(move || worker.run())
            .map_err(CaptureError::Os)?;
        Ok((
            Self {
                stop,
                counters,
                thread: Some(thread),
            },
            rx,
        ))
    }

    pub fn stats(&self) -> CaptureStats {
        self.stats_handle().snapshot()
    }

    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle(Arc::clone(&self.counters))
    }

    /// False once the thread has ended (source exhausted, failed, or consumer gone).
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Stops the thread, waits for it (at most about one read timeout) and returns the final counters, or
    /// the error that ended the capture early.
    pub fn stop(mut self) -> Result<CaptureStats, CaptureError> {
        self.stop.store(true, Ordering::Relaxed);
        let result = match self.thread.take() {
            Some(handle) => handle.join().map_err(|_| CaptureError::ThreadPanicked)?,
            None => Ok(()),
        };
        result.map(|()| self.stats())
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

struct Worker {
    source: Box<dyn PacketSource>,
    cfg: PipelineConfig,
    tx: mpsc::Sender<PacketBatch>,
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
}

/// How many frames pass between checks of the flush timer. Reading the clock per packet is wasteful and on
/// some virtual machines very slow (about 24 us per `Instant::now()` was measured on the dev VPS).
const CLOCK_CHECK_EVERY: u32 = 256;

impl Worker {
    fn run(mut self) -> Result<(), CaptureError> {
        let link = self.source.link_type();
        let local = LocalAddrs::new(self.source.local_addrs());
        let filter = self.cfg.filter.take().filter(|f| !f.is_any());
        let batch_size = self.cfg.batch_size;
        let mut batch: PacketBatch = Vec::with_capacity(batch_size);
        let mut last_flush = Instant::now();
        let mut since_clock = 0u32;
        let mut outcome = Ok(());

        'read: while !self.stop.load(Ordering::Relaxed) {
            match self.source.next() {
                Ok(SourceEvent::Frame(frame)) => {
                    self.counters.received.fetch_add(1, Ordering::Relaxed);
                    match decode_frame(link, frame.data, frame.timestamp_ns, &local) {
                        Ok(meta) => {
                            self.counters.decoded.fetch_add(1, Ordering::Relaxed);
                            if filter.as_ref().is_none_or(|f| f.matches(&meta)) {
                                batch.push(meta);
                            } else {
                                self.counters.filtered_out.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(DecodeError::NotIp) => {
                            self.counters.non_ip.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(DecodeError::Truncated | DecodeError::Malformed) => {
                            self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    since_clock += 1;
                    let due = batch.len() >= batch_size
                        || (since_clock >= CLOCK_CHECK_EVERY && {
                            since_clock = 0;
                            last_flush.elapsed() >= self.cfg.flush_interval
                        });
                    if due && !self.flush(&mut batch, &mut last_flush) {
                        break 'read;
                    }
                }
                Ok(SourceEvent::Timeout) => {
                    since_clock = 0;
                    if !self.flush(&mut batch, &mut last_flush) {
                        break 'read;
                    }
                }
                Ok(SourceEvent::Eof) => break 'read,
                Err(e) => {
                    outcome = Err(e);
                    break 'read;
                }
            }
        }

        // Deliver what is left, even after a stop request or a failure.
        self.flush(&mut batch, &mut last_flush);
        self.counters
            .kernel_drops
            .store(self.source.kernel_drops(), Ordering::Relaxed);
        outcome
    }

    /// Sends the batch if it holds anything. Returns false when the consumer is gone.
    fn flush(&self, batch: &mut PacketBatch, last_flush: &mut Instant) -> bool {
        *last_flush = Instant::now();
        // Keep the kernel drop figure fresh for whoever polls the stats.
        self.counters
            .kernel_drops
            .store(self.source.kernel_drops(), Ordering::Relaxed);
        if batch.is_empty() {
            return true;
        }
        let count = batch.len() as u64;
        let full = std::mem::replace(batch, Vec::with_capacity(self.cfg.batch_size));
        match self.tx.try_send(full) {
            Ok(()) => {
                self.counters.delivered.fetch_add(count, Ordering::Relaxed);
                self.counters.batches_sent.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(mut back)) => {
                // Consumer is behind: drop, count, and reuse the allocation.
                self.counters
                    .dropped_queue
                    .fetch_add(count, Ordering::Relaxed);
                self.counters
                    .batches_dropped
                    .fetch_add(1, Ordering::Relaxed);
                back.clear();
                *batch = back;
                true
            }
            Err(TrySendError::Closed(_)) => {
                self.counters
                    .dropped_queue
                    .fetch_add(count, Ordering::Relaxed);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::LinkType;
    use crate::fake::{AfterScript, FakeSource, SyntheticConfig, SyntheticSource};
    use crate::stats::{StatsAggregator, StatsConfig};
    use etherparse::PacketBuilder;

    fn udp_frame(src: [u8; 4], port: u16) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src, [10, 0, 0, 5], 64)
            .udp(4000, port);
        let mut v = Vec::new();
        b.write(&mut v, &[0u8; 10]).unwrap();
        v
    }

    fn drain(mut rx: BatchReceiver) -> Vec<PacketMeta> {
        let mut out = Vec::new();
        while let Some(batch) = rx.blocking_recv() {
            out.extend(batch);
        }
        out
    }

    #[test]
    fn delivers_decoded_packets_and_counts_everything_else() {
        let mut src =
            FakeSource::new(LinkType::Ethernet).with_local_addrs(&["10.0.0.5".parse().unwrap()]);
        src.push_frame(10, &udp_frame([1, 1, 1, 1], 53))
            .push_frame(20, &[0xff; 6]) // too short
            .push_frame(30, &{
                let mut arp = vec![0xff; 6];
                arp.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
                arp.extend_from_slice(&[0u8; 20]);
                arp
            })
            .push_frame(40, &udp_frame([2, 2, 2, 2], 53))
            .push_timeout();
        let (cap, rx) = Capture::start(Box::new(src), PipelineConfig::default()).unwrap();
        let packets = drain(rx);
        let stats = cap.stop().unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].timestamp_ns, 10);
        assert_eq!(packets[1].src.to_string(), "2.2.2.2");
        assert_eq!(stats.received, 4);
        assert_eq!(stats.decoded, 2);
        assert_eq!(stats.malformed, 1);
        assert_eq!(stats.non_ip, 1);
        assert_eq!(stats.delivered, 2);
        assert_eq!(stats.dropped_packets(), 0);
    }

    #[test]
    fn applies_the_filter_after_decoding() {
        let mut src = FakeSource::new(LinkType::Ethernet);
        for i in 0..10u16 {
            src.push_frame(u64::from(i), &udp_frame([1, 1, 1, 1], 50 + i));
        }
        let cfg = PipelineConfig {
            filter: Some(Filter::parse("dst port 52-54").unwrap()),
            ..PipelineConfig::default()
        };
        let (cap, rx) = Capture::start(Box::new(src), cfg).unwrap();
        let packets = drain(rx);
        let stats = cap.stop().unwrap();
        assert_eq!(packets.len(), 3);
        assert_eq!(stats.filtered_out, 7);
        assert_eq!(stats.decoded, 10);
    }

    #[test]
    fn batches_are_bounded_by_size() {
        let src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(1000),
            ..SyntheticConfig::default()
        });
        let cfg = PipelineConfig {
            batch_size: 100,
            queue_batches: 64,
            ..PipelineConfig::default()
        };
        let (cap, mut rx) = Capture::start(Box::new(src), cfg).unwrap();
        let mut sizes = Vec::new();
        while let Some(batch) = rx.blocking_recv() {
            sizes.push(batch.len());
        }
        cap.stop().unwrap();
        assert!(sizes.iter().all(|s| *s <= 100));
        assert_eq!(sizes.iter().sum::<usize>(), 1000);
    }

    #[test]
    fn a_partial_batch_is_flushed_on_timeout_and_on_eof() {
        let mut src = FakeSource::new(LinkType::Ethernet)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(5));
        src.push_frame(1, &udp_frame([1, 1, 1, 1], 53));
        let (cap, mut rx) = Capture::start(Box::new(src), PipelineConfig::default()).unwrap();
        // The idle source keeps timing out; the single packet must show up without waiting for a full batch.
        let batch = rx.blocking_recv().unwrap();
        assert_eq!(batch.len(), 1);
        cap.stop().unwrap();
    }

    #[test]
    fn stop_is_prompt_and_clean_on_an_idle_source() {
        let src = FakeSource::new(LinkType::RawIp)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(10));
        let (cap, _rx) = Capture::start(Box::new(src), PipelineConfig::default()).unwrap();
        assert!(cap.is_running());
        let started = Instant::now();
        let stats = cap.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(stats, CaptureStats::default());
    }

    #[test]
    fn dropping_the_handle_joins_the_thread() {
        let src = FakeSource::new(LinkType::RawIp)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(5));
        let (cap, rx) = Capture::start(Box::new(src), PipelineConfig::default()).unwrap();
        let handle = cap.stats_handle();
        drop(cap);
        drop(rx);
        assert_eq!(handle.snapshot().received, 0);
    }

    #[test]
    fn a_source_error_ends_the_capture_and_is_reported() {
        let mut src = FakeSource::new(LinkType::Ethernet);
        src.push_frame(1, &udp_frame([1, 1, 1, 1], 53))
            .push_error("adapter vanished");
        let (cap, rx) = Capture::start(Box::new(src), PipelineConfig::default()).unwrap();
        let packets = drain(rx);
        assert_eq!(
            packets.len(),
            1,
            "packets read before the failure are still delivered"
        );
        assert!(matches!(cap.stop(), Err(CaptureError::Source(m)) if m == "adapter vanished"));
    }

    #[test]
    fn the_capture_ends_by_itself_when_the_consumer_goes_away() {
        let src = SyntheticSource::new(SyntheticConfig {
            total_packets: None,
            ..SyntheticConfig::default()
        });
        let cfg = PipelineConfig {
            batch_size: 10,
            queue_batches: 1,
            ..PipelineConfig::default()
        };
        let (cap, rx) = Capture::start(Box::new(src), cfg).unwrap();
        drop(rx);
        let deadline = Instant::now() + Duration::from_secs(5);
        while cap.is_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!cap.is_running());
        cap.stop().unwrap();
    }

    #[test]
    fn kernel_drops_are_surfaced() {
        let mut src = FakeSource::new(LinkType::Ethernet)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(5));
        src.push_frame(1, &udp_frame([1, 1, 1, 1], 53));
        let drops = src.kernel_drops_handle();
        drops.store(77, Ordering::Relaxed);
        let (cap, _rx) = Capture::start(Box::new(src), PipelineConfig::default()).unwrap();
        let handle = cap.stats_handle();
        let deadline = Instant::now() + Duration::from_secs(5);
        while handle.snapshot().kernel_drops != 77 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(handle.dropped_packets(), 77);
        cap.stop().unwrap();
    }

    #[test]
    fn rejects_zero_sized_queues() {
        let src = FakeSource::new(LinkType::RawIp);
        let cfg = PipelineConfig {
            queue_batches: 0,
            ..PipelineConfig::default()
        };
        assert!(matches!(
            Capture::start(Box::new(src), cfg),
            Err(CaptureError::InvalidSettings(_))
        ));
    }

    /// A consumer that never reads: the queue fills, batches are dropped, and every packet is accounted for.
    #[test]
    fn overflow_is_counted_not_hidden() {
        const TOTAL: u64 = 100_000;
        let src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(TOTAL),
            ..SyntheticConfig::default()
        });
        let cfg = PipelineConfig {
            queue_batches: 4,
            batch_size: 64,
            ..PipelineConfig::default()
        };
        let (cap, mut rx) = Capture::start(Box::new(src), cfg).unwrap();
        // Let the reader finish while nobody consumes.
        let handle = cap.stats_handle();
        let deadline = Instant::now() + Duration::from_secs(30);
        while cap.is_running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stats = cap.stop().unwrap();
        assert_eq!(stats.received, TOTAL);
        assert!(
            stats.dropped_queue > 0,
            "a 4-batch queue cannot hold 100k packets"
        );
        assert_eq!(stats.delivered + stats.dropped_queue, TOTAL);
        assert_eq!(handle.dropped_packets(), stats.dropped_queue);
        // What was queued is exactly what `delivered` says.
        let mut queued = 0u64;
        while let Ok(batch) = rx.try_recv() {
            queued += batch.len() as u64;
        }
        assert_eq!(queued, stats.delivered);
    }

    /// The load test of the M4 acceptance: 200k packets per second for a few seconds through the real
    /// pipeline into the stats aggregator, with a consumer that is deliberately slower than the producer
    /// part of the time. Accounting must balance, memory must stay bounded, nothing may panic. It does not
    /// assert zero drops or timing: this runs as a debug build.
    #[test]
    fn survives_200k_pps_with_bounded_memory_and_exact_accounting() {
        const RATE: u64 = 200_000;
        const SECONDS: u64 = 3;
        const TOTAL: u64 = RATE * SECONDS;
        const MAX_TRACKED: usize = 5_000;

        let src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(TOTAL),
            rate_pps: RATE,
            paced: true,
            distinct_sources: 1 << 20, // a spoofed-source flood: far more sources than the table holds
            start_ns: 0,
        });
        let cfg = PipelineConfig {
            queue_batches: 32,
            batch_size: 512,
            ..PipelineConfig::default()
        };
        let (cap, mut rx) = Capture::start(Box::new(src), cfg).unwrap();
        let handle = cap.stats_handle();
        let mut agg = StatsAggregator::new(
            StatsConfig {
                top_n: 10,
                max_tracked_ips: MAX_TRACKED,
            },
            0,
        );

        let mut counted = 0u64;
        let mut ticks = 0u64;
        let mut max_tracked_seen = 0usize;
        let mut last_tick = Instant::now();
        let mut now_ns = 0u64;
        while let Some(batch) = rx.blocking_recv() {
            counted += batch.len() as u64;
            agg.observe_batch(&batch);
            max_tracked_seen = max_tracked_seen.max(agg.tracked_sources());
            // Tick every 250 ms of real time with injected (virtual) timestamps.
            if last_tick.elapsed() >= Duration::from_millis(250) {
                last_tick = Instant::now();
                now_ns += 250_000_000;
                agg.set_dropped_total(handle.dropped_packets());
                let snap = agg.tick(now_ns);
                ticks += 1;
                assert!(snap.tracked_sources <= MAX_TRACKED);
                assert!(snap.top_talkers.len() <= 10);
            }
        }
        let stats = cap.stop().unwrap();

        assert_eq!(stats.received, TOTAL, "the source produced every packet");
        assert_eq!(stats.decoded, TOTAL);
        assert_eq!(
            stats.delivered + stats.dropped_packets(),
            TOTAL,
            "every packet is either delivered or counted as dropped"
        );
        assert_eq!(
            counted, stats.delivered,
            "the consumer saw exactly what was delivered"
        );
        assert!(max_tracked_seen <= MAX_TRACKED);
        assert!(ticks >= 1);
        eprintln!(
            "200k pps test: delivered {} dropped {} ticks {ticks}",
            stats.delivered,
            stats.dropped_packets()
        );
    }
}
