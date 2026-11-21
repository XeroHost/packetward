// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Sources that need no network: a scripted replay ([`FakeSource`]) and a generator of synthetic traffic
//! for load tests ([`SyntheticSource`]). Public so the engine and other crates can test against them.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::backend::{Frame, LinkType, PacketSource, SourceEvent, DEFAULT_READ_TIMEOUT};
use crate::error::CaptureError;

#[derive(Debug, Clone)]
enum Step {
    Frame {
        timestamp_ns: u64,
        data: Vec<u8>,
        original_len: u32,
    },
    Timeout,
    Error(String),
}

/// What a [`FakeSource`] does once its script is used up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterScript {
    /// Report [`SourceEvent::Eof`].
    Eof,
    /// Behave like an idle live interface: report a timeout (after sleeping `read_timeout`) forever.
    Idle,
}

/// Replays a script of frames, timeouts and errors.
pub struct FakeSource {
    link: LinkType,
    local: Vec<IpAddr>,
    script: VecDeque<Step>,
    current: Vec<u8>,
    after: AfterScript,
    read_timeout: Duration,
    kernel_drops: Arc<AtomicU64>,
}

impl FakeSource {
    pub fn new(link: LinkType) -> Self {
        Self {
            link,
            local: Vec::new(),
            script: VecDeque::new(),
            current: Vec::new(),
            after: AfterScript::Eof,
            read_timeout: DEFAULT_READ_TIMEOUT,
            kernel_drops: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_local_addrs(mut self, addrs: &[IpAddr]) -> Self {
        self.local = addrs.to_vec();
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn after_script(mut self, after: AfterScript) -> Self {
        self.after = after;
        self
    }

    /// The value [`PacketSource::kernel_drops`] reports; the returned handle changes it while running.
    pub fn kernel_drops_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.kernel_drops)
    }

    /// Queues a frame whose wire length equals its captured length.
    pub fn push_frame(&mut self, timestamp_ns: u64, data: &[u8]) -> &mut Self {
        self.push_truncated_frame(timestamp_ns, data, data.len() as u32)
    }

    /// Queues a frame that was cut to `data.len()` bytes from `original_len` on the wire.
    pub fn push_truncated_frame(
        &mut self,
        timestamp_ns: u64,
        data: &[u8],
        original_len: u32,
    ) -> &mut Self {
        self.script.push_back(Step::Frame {
            timestamp_ns,
            data: data.to_vec(),
            original_len: original_len.max(data.len() as u32),
        });
        self
    }

    pub fn push_timeout(&mut self) -> &mut Self {
        self.script.push_back(Step::Timeout);
        self
    }

    pub fn push_error(&mut self, message: &str) -> &mut Self {
        self.script.push_back(Step::Error(message.to_owned()));
        self
    }
}

impl PacketSource for FakeSource {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn local_addrs(&self) -> &[IpAddr] {
        &self.local
    }

    fn next(&mut self) -> Result<SourceEvent<'_>, CaptureError> {
        match self.script.pop_front() {
            Some(Step::Frame {
                timestamp_ns,
                data,
                original_len,
            }) => {
                self.current = data;
                Ok(SourceEvent::Frame(Frame {
                    timestamp_ns,
                    data: &self.current,
                    original_len,
                }))
            }
            Some(Step::Timeout) => Ok(SourceEvent::Timeout),
            Some(Step::Error(message)) => Err(CaptureError::Source(message)),
            None => match self.after {
                AfterScript::Eof => Ok(SourceEvent::Eof),
                AfterScript::Idle => {
                    std::thread::sleep(self.read_timeout);
                    Ok(SourceEvent::Timeout)
                }
            },
        }
    }

    fn kernel_drops(&self) -> u64 {
        self.kernel_drops.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------------------------
// Synthetic traffic
// ---------------------------------------------------------------------------------------------

/// Local address of the synthetic host; every generated packet is addressed to it (inbound).
pub const SYNTHETIC_LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5));
const SYNTHETIC_LEN: usize = 40;
/// Packets generated between two looks at the clock when pacing.
const PACE_GROUP: u64 = 200;

#[derive(Debug, Clone, Copy)]
pub struct SyntheticConfig {
    /// Stop after this many packets (`None` = endless).
    pub total_packets: Option<u64>,
    /// Packets per second of *virtual* time stamped on the frames, and, when `paced` is set, of real time.
    pub rate_pps: u64,
    /// Sleep so that the real delivery rate matches `rate_pps`. Off = generate as fast as asked.
    pub paced: bool,
    /// Number of distinct source addresses cycled through (at most 2^24).
    pub distinct_sources: u32,
    pub start_ns: u64,
}

impl Default for SyntheticConfig {
    fn default() -> Self {
        Self {
            total_packets: Some(1000),
            rate_pps: 200_000,
            paced: false,
            distinct_sources: 1000,
            start_ns: 1_700_000_000_000_000_000,
        }
    }
}

/// Endless-or-finite UDP flood of raw IPv4 packets (40 bytes each). One fixed buffer is patched in place,
/// so generating a packet allocates nothing.
pub struct SyntheticSource {
    cfg: SyntheticConfig,
    buf: [u8; SYNTHETIC_LEN],
    counter: u64,
    started: Instant,
    local: [IpAddr; 1],
}

impl SyntheticSource {
    pub fn new(cfg: SyntheticConfig) -> Self {
        let mut buf = [0u8; SYNTHETIC_LEN];
        buf[0] = 0x45; // IPv4, 20-byte header
        buf[3] = SYNTHETIC_LEN as u8; // total length
        buf[8] = 64; // TTL
        buf[9] = 17; // UDP
        buf[16..20].copy_from_slice(&[10, 0, 0, 5]);
        buf[20..22].copy_from_slice(&40_000u16.to_be_bytes());
        buf[22..24].copy_from_slice(&53u16.to_be_bytes());
        buf[25] = (SYNTHETIC_LEN - 20) as u8; // UDP length
        Self {
            cfg: SyntheticConfig {
                rate_pps: cfg.rate_pps.max(1),
                distinct_sources: cfg.distinct_sources.clamp(1, 1 << 24),
                ..cfg
            },
            buf,
            counter: 0,
            started: Instant::now(),
            local: [SYNTHETIC_LOCAL],
        }
    }

    /// Number of packets generated so far.
    pub fn generated(&self) -> u64 {
        self.counter
    }
}

impl PacketSource for SyntheticSource {
    fn link_type(&self) -> LinkType {
        LinkType::RawIp
    }

    fn local_addrs(&self) -> &[IpAddr] {
        &self.local
    }

    fn next(&mut self) -> Result<SourceEvent<'_>, CaptureError> {
        if self
            .cfg
            .total_packets
            .is_some_and(|total| self.counter >= total)
        {
            return Ok(SourceEvent::Eof);
        }
        let n = self.counter;
        let virtual_offset_ns = u128::from(n) * 1_000_000_000 / u128::from(self.cfg.rate_pps);
        // Reading the clock can be slow on virtual machines, so pace in small groups, not per packet.
        if self.cfg.paced && n.is_multiple_of(PACE_GROUP) {
            let due = Duration::from_nanos(u64::try_from(virtual_offset_ns).unwrap_or(u64::MAX));
            loop {
                let elapsed = self.started.elapsed();
                if elapsed >= due {
                    break;
                }
                let ahead = due - elapsed;
                if ahead > Duration::from_millis(20) {
                    std::thread::sleep(ahead / 2);
                } else {
                    // Sleeping is too coarse for the last milliseconds (about 16 ms on Windows).
                    std::thread::yield_now();
                }
            }
        }
        let source = (n % u64::from(self.cfg.distinct_sources)) as u32;
        self.buf[12] = 100;
        self.buf[13..16].copy_from_slice(&source.to_be_bytes()[1..4]);
        self.counter += 1;
        Ok(SourceEvent::Frame(Frame {
            timestamp_ns: self
                .cfg
                .start_ns
                .saturating_add(u64::try_from(virtual_offset_ns).unwrap_or(u64::MAX)),
            data: &self.buf,
            original_len: SYNTHETIC_LEN as u32,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{decode_frame, LocalAddrs};

    #[test]
    fn script_plays_in_order_then_ends() {
        let mut src = FakeSource::new(LinkType::RawIp);
        src.push_frame(1, &[1, 2, 3])
            .push_timeout()
            .push_truncated_frame(2, &[4, 5], 100)
            .push_error("boom");
        assert!(
            matches!(src.next(), Ok(SourceEvent::Frame(f)) if f.timestamp_ns == 1 && f.data == [1, 2, 3] && f.original_len == 3)
        );
        assert!(matches!(src.next(), Ok(SourceEvent::Timeout)));
        assert!(
            matches!(src.next(), Ok(SourceEvent::Frame(f)) if f.original_len == 100 && f.data.len() == 2)
        );
        assert!(matches!(src.next(), Err(CaptureError::Source(m)) if m == "boom"));
        assert!(matches!(src.next(), Ok(SourceEvent::Eof)));
    }

    #[test]
    fn idle_sources_time_out_instead_of_ending() {
        let mut src = FakeSource::new(LinkType::RawIp)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(1));
        assert!(matches!(src.next(), Ok(SourceEvent::Timeout)));
        assert!(matches!(src.next(), Ok(SourceEvent::Timeout)));
    }

    #[test]
    fn synthetic_packets_decode_and_cycle_sources() {
        let mut src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(5),
            rate_pps: 1000,
            distinct_sources: 3,
            start_ns: 0,
            paced: false,
        });
        let local = LocalAddrs::new(src.local_addrs());
        let mut seen = Vec::new();
        while let Ok(SourceEvent::Frame(f)) = src.next() {
            let m = decode_frame(LinkType::RawIp, f.data, f.timestamp_ns, &local).unwrap();
            assert_eq!(m.len, 40);
            assert_eq!(m.direction, pw_core::Direction::Inbound);
            seen.push((m.src.to_string(), m.timestamp_ns));
        }
        assert_eq!(src.generated(), 5);
        assert_eq!(seen[0], ("100.0.0.0".to_owned(), 0));
        assert_eq!(seen[1], ("100.0.0.1".to_owned(), 1_000_000));
        assert_eq!(seen[3].0, "100.0.0.0");
    }
}
