// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Capture to pcapng: a timed capture (duration and size limits) or a ring buffer bounded by total size.
//!
//! The recorder runs on its own thread with its **own** [`PacketSource`], independent of the live
//! pipeline: writing to disk may block, and that must never stall the pipeline's hot path. (Kernel buffers
//! absorb short stalls; whatever they cannot hold shows up in [`RecordingSummary::kernel_drops`].)
//!
//! Safety properties:
//! * Everything is written inside the directory the caller names, which must already exist (the caller
//!   chooses an access-controlled location). File names are generated here from a sanitized prefix
//!   (ASCII letters, digits, `-`, `_`), a start time and a sequence number; no caller text reaches the
//!   path unfiltered.
//! * Files are created exclusively as `*.pcapng.partial`, flushed and fsynced, then renamed to `*.pcapng`
//!   (atomic on the same volume). A reader never sees a half-written `.pcapng`.
//! * The ring deletes only segments this recorder created and tracks itself, never anything it finds in
//!   the directory.
//! * Default snap length is 128 bytes (headers only). Full payload is an explicit [`Payload::Full`].
//!   Timestamps are stored with nanosecond resolution.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption, InterfaceTsResolution,
};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use pw_core::PacketMeta;
use serde::{Deserialize, Serialize};

use crate::backend::{CaptureOpts, LinkType, PacketSource, SourceEvent, DEFAULT_SNAPLEN};
use crate::decode::{decode_frame, LocalAddrs};
use crate::error::CaptureError;
use crate::filter::Filter;

pub const DEFAULT_RING_TOTAL_BYTES: u64 = 200 * 1024 * 1024;
pub const DEFAULT_RING_SEGMENT_BYTES: u64 = 20 * 1024 * 1024;
pub const DEFAULT_TIMED_MAX_BYTES: u64 = 500 * 1024 * 1024;
/// Snap length used for [`Payload::Full`].
pub const FULL_SNAPLEN: u32 = 262_144;
const MIN_SEGMENT_BYTES: u64 = 1024;
const MIN_SNAPLEN: u32 = 64;
const MAX_NAME_LEN: usize = 40;
/// Frames between looks at the clock for the duration limit.
const CLOCK_CHECK_EVERY: u32 = 256;

/// How much of each packet is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payload {
    /// The first `snaplen` bytes only (headers). Default: 128.
    Headers { snaplen: u32 },
    /// Whole packets, payload included. Must be chosen explicitly; the UI warns about it.
    Full,
}

impl Default for Payload {
    fn default() -> Self {
        Self::Headers {
            snaplen: DEFAULT_SNAPLEN,
        }
    }
}

impl Payload {
    pub fn snaplen(self) -> u32 {
        match self {
            Self::Headers { snaplen } => snaplen.clamp(MIN_SNAPLEN, FULL_SNAPLEN),
            Self::Full => FULL_SNAPLEN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordMode {
    /// One file; ends after `max_duration` or when it reaches `max_bytes`.
    Timed {
        max_duration: Duration,
        max_bytes: u64,
    },
    /// Rolling segments; the oldest are deleted so that all files together stay within `max_total_bytes`.
    /// Runs until stopped.
    Ring {
        max_total_bytes: u64,
        segment_bytes: u64,
    },
}

#[derive(Debug, Clone)]
pub struct RecordSpec {
    /// Existing directory to write into.
    pub dir: PathBuf,
    /// File name prefix; characters other than ASCII letters, digits, `-` and `_` become `_`.
    pub name: String,
    pub mode: RecordMode,
    pub payload: Payload,
    /// Only matching packets are written (evaluated in Rust). Non-IP frames never match a filter.
    pub filter: Option<Filter>,
    /// Stored in the pcapng interface description.
    pub interface_name: Option<String>,
}

impl RecordSpec {
    pub fn timed(dir: impl Into<PathBuf>, name: &str, duration: Duration) -> Self {
        Self {
            dir: dir.into(),
            name: name.to_owned(),
            mode: RecordMode::Timed {
                max_duration: duration,
                max_bytes: DEFAULT_TIMED_MAX_BYTES,
            },
            payload: Payload::default(),
            filter: None,
            interface_name: None,
        }
    }

    /// Ring buffer with the defaults: 200 MB in 20 MB segments.
    pub fn ring(dir: impl Into<PathBuf>, name: &str) -> Self {
        Self {
            dir: dir.into(),
            name: name.to_owned(),
            mode: RecordMode::Ring {
                max_total_bytes: DEFAULT_RING_TOTAL_BYTES,
                segment_bytes: DEFAULT_RING_SEGMENT_BYTES,
            },
            payload: Payload::default(),
            filter: None,
            interface_name: None,
        }
    }

    /// The options a source should be opened with for this recording (snap length, BPF pre-filter).
    pub fn capture_opts(&self) -> CaptureOpts {
        CaptureOpts {
            snaplen: self.payload.snaplen(),
            filter: self.filter.clone(),
            ..CaptureOpts::default()
        }
    }

    fn validate(&self) -> Result<(), CaptureError> {
        let bad = |m: &str| Err(CaptureError::InvalidSettings(m.to_owned()));
        if !self.dir.is_dir() {
            return bad("the capture directory does not exist");
        }
        match self.mode {
            RecordMode::Timed {
                max_duration,
                max_bytes,
            } => {
                if max_duration.is_zero() {
                    return bad("capture duration must be longer than zero");
                }
                if max_bytes < MIN_SEGMENT_BYTES {
                    return bad("capture size limit is too small");
                }
            }
            RecordMode::Ring {
                max_total_bytes,
                segment_bytes,
            } => {
                if segment_bytes < MIN_SEGMENT_BYTES {
                    return bad("ring segment size is too small");
                }
                if max_total_bytes < segment_bytes.saturating_mul(2) {
                    return bad("ring total size must hold at least two segments");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    /// [`Recorder::stop`] was called.
    Requested,
    /// The timed capture reached its duration.
    Duration,
    /// The timed capture reached its size limit.
    SizeLimit,
    /// The source ended (a finite replay).
    SourceEnded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingSummary {
    /// Finalized files that exist on disk, oldest first.
    pub files: Vec<PathBuf>,
    pub packets_written: u64,
    /// Bytes written to all files, including ring segments deleted since.
    pub bytes_written: u64,
    /// Packets rejected by the filter.
    pub packets_filtered: u64,
    pub segments_deleted: u64,
    /// Dropped by the OS or driver, as reported by the source.
    pub kernel_drops: u64,
    pub reason: StopReason,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordProgress {
    pub packets_written: u64,
    pub bytes_written: u64,
    pub packets_filtered: u64,
}

#[derive(Default)]
struct Progress {
    packets_written: AtomicU64,
    bytes_written: AtomicU64,
    packets_filtered: AtomicU64,
}

/// A running recording. Dropping it stops the recording and finalizes the current file.
pub struct Recorder {
    stop: Arc<AtomicBool>,
    progress: Arc<Progress>,
    thread: Option<JoinHandle<Result<RecordingSummary, CaptureError>>>,
}

impl Recorder {
    pub fn start(source: Box<dyn PacketSource>, spec: RecordSpec) -> Result<Self, CaptureError> {
        spec.validate()?;
        let stem = sanitize(&spec.name);
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        let job = Job {
            source,
            spec,
            stem,
            stop: Arc::clone(&stop),
            progress: Arc::clone(&progress),
        };
        let thread = std::thread::Builder::new()
            .name("pw-record".to_owned())
            .spawn(move || job.run())
            .map_err(CaptureError::Os)?;
        Ok(Self {
            stop,
            progress,
            thread: Some(thread),
        })
    }

    pub fn progress(&self) -> RecordProgress {
        RecordProgress {
            packets_written: self.progress.packets_written.load(Ordering::Relaxed),
            bytes_written: self.progress.bytes_written.load(Ordering::Relaxed),
            packets_filtered: self.progress.packets_filtered.load(Ordering::Relaxed),
        }
    }

    /// False once the recording has ended by itself (limit reached, source ended or failed).
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Asks the recording to end, finalizes the current file and returns what was written.
    pub fn stop(self) -> Result<RecordingSummary, CaptureError> {
        self.stop.store(true, Ordering::Relaxed);
        self.wait()
    }

    /// Waits for the recording to end on its own (timed mode) and returns what was written.
    pub fn wait(mut self) -> Result<RecordingSummary, CaptureError> {
        match self.thread.take() {
            Some(handle) => handle.join().map_err(|_| CaptureError::ThreadPanicked)?,
            None => Err(CaptureError::ThreadPanicked),
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .take(MAX_NAME_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "capture".to_owned()
    } else {
        cleaned
    }
}

fn datalink(link: LinkType) -> DataLink {
    match link {
        LinkType::Ethernet => DataLink::ETHERNET,
        // LINKTYPE_RAW (101): the packet starts with the IPv4 or IPv6 header; Wireshark tells them apart.
        LinkType::RawIp => DataLink::RAW,
        LinkType::Null => DataLink::NULL,
    }
}

// ---------------------------------------------------------------------------------------------
// Segment files
// ---------------------------------------------------------------------------------------------

struct CountingWriter<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct Segment {
    writer: PcapNgWriter<CountingWriter<BufWriter<File>>>,
    partial: PathBuf,
    target: PathBuf,
    packets: u64,
    snaplen: u32,
}

impl Segment {
    fn create(
        dir: &Path,
        stem: &str,
        epoch_secs: u64,
        seq: &mut u32,
        link: LinkType,
        snaplen: u32,
        interface_name: Option<&str>,
    ) -> Result<Self, CaptureError> {
        // Find a free name; the partial file is created exclusively so two recorders never share one.
        let mut attempts = 0;
        let (target, partial, file) = loop {
            *seq += 1;
            attempts += 1;
            let base = format!("{stem}-{epoch_secs}-{:04}", *seq);
            let target = dir.join(format!("{base}.pcapng"));
            let partial = dir.join(format!("{base}.pcapng.partial"));
            if !target.exists() {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&partial)
                {
                    Ok(file) => break (target, partial, file),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempts < 1000 => {}
                    Err(e) => return Err(CaptureError::io(&partial, e)),
                }
            }
            if attempts >= 1000 {
                return Err(CaptureError::io(
                    dir,
                    io::Error::new(io::ErrorKind::AlreadyExists, "no free capture file name"),
                ));
            }
        };

        let counting = CountingWriter {
            inner: BufWriter::with_capacity(64 * 1024, file),
            count: 0,
        };
        let mut writer =
            PcapNgWriter::new(counting).map_err(|e| CaptureError::Pcapng(e.to_string()))?;
        let mut idb = InterfaceDescriptionBlock::new(datalink(link), snaplen);
        idb.options.push(InterfaceDescriptionOption::IfTsResol(
            InterfaceTsResolution::NANO,
        ));
        if let Some(name) = interface_name {
            idb.options
                .push(InterfaceDescriptionOption::IfName(Cow::Owned(
                    name.to_owned(),
                )));
        }
        writer
            .write_pcapng_block(idb)
            .map_err(|e| CaptureError::Pcapng(e.to_string()))?;
        Ok(Self {
            writer,
            partial,
            target,
            packets: 0,
            snaplen,
        })
    }

    fn bytes(&self) -> u64 {
        self.writer.get_ref().count
    }

    fn write_packet(
        &mut self,
        timestamp_ns: u64,
        data: &[u8],
        original_len: u32,
    ) -> Result<(), CaptureError> {
        let keep = data.len().min(self.snaplen as usize);
        let block = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_nanos(timestamp_ns),
            original_len: original_len.max(keep as u32),
            data: Cow::Borrowed(&data[..keep]),
            options: Vec::new(),
        };
        self.writer
            .write_pcapng_block(block)
            .map_err(|e| CaptureError::Pcapng(e.to_string()))?;
        self.packets += 1;
        Ok(())
    }

    /// Flushes, fsyncs and renames the file into place. Returns its path and size.
    fn finalize(self) -> Result<(PathBuf, u64), CaptureError> {
        let Segment {
            writer,
            partial,
            target,
            ..
        } = self;
        let counting = writer.into_inner();
        let size = counting.count;
        let file = counting
            .inner
            .into_inner()
            .map_err(|e| CaptureError::io(&partial, e.into_error()))?;
        file.sync_all().map_err(|e| CaptureError::io(&partial, e))?;
        drop(file);
        fs::rename(&partial, &target).map_err(|e| CaptureError::io(&target, e))?;
        Ok((target, size))
    }

    /// Gives up on the segment, removing its partial file.
    fn discard(self) {
        let partial = self.partial.clone();
        drop(self);
        let _ = fs::remove_file(partial);
    }
}

// ---------------------------------------------------------------------------------------------
// The recording thread
// ---------------------------------------------------------------------------------------------

struct Job {
    source: Box<dyn PacketSource>,
    spec: RecordSpec,
    stem: String,
    stop: Arc<AtomicBool>,
    progress: Arc<Progress>,
}

struct Finished {
    path: PathBuf,
    size: u64,
}

impl Job {
    fn run(mut self) -> Result<RecordingSummary, CaptureError> {
        let link = self.source.link_type();
        let local = LocalAddrs::new(self.source.local_addrs());
        let filter = self.spec.filter.clone().filter(|f| !f.is_any());
        let snaplen = self.spec.payload.snaplen();
        let epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let started = Instant::now();
        let mut seq = 0u32;
        let mut segment = Segment::create(
            &self.spec.dir,
            &self.stem,
            epoch_secs,
            &mut seq,
            link,
            snaplen,
            self.spec.interface_name.as_deref(),
        )?;

        let mut finished: VecDeque<Finished> = VecDeque::new();
        let mut finished_bytes = 0u64;
        let mut written_total = 0u64; // bytes of segments already finalized (including deleted ones)
        let mut packets_total = 0u64;
        let mut deleted = 0u64;
        let mut filtered = 0u64;
        let mut reason = StopReason::Requested;
        let mut failure: Option<CaptureError> = None;

        // The clock is read when idle and every CLOCK_CHECK_EVERY frames, not per packet: on some virtual
        // machines `Instant::now()` costs tens of microseconds, which would cap the recording rate.
        let mut check_clock = true;
        let mut since_clock = 0u32;
        'read: while !self.stop.load(Ordering::Relaxed) {
            // (Every event below sets `check_clock` again, so it needs no reset here.)
            if check_clock {
                since_clock = 0;
                if let RecordMode::Timed { max_duration, .. } = self.spec.mode {
                    if started.elapsed() >= max_duration {
                        reason = StopReason::Duration;
                        break 'read;
                    }
                }
            }
            let event = match self.source.next() {
                Ok(event) => event,
                Err(e) => {
                    failure = Some(e);
                    break 'read;
                }
            };
            let frame = match event {
                SourceEvent::Frame(frame) => {
                    since_clock += 1;
                    check_clock = since_clock >= CLOCK_CHECK_EVERY;
                    frame
                }
                SourceEvent::Timeout => {
                    check_clock = true;
                    continue;
                }
                SourceEvent::Eof => {
                    reason = StopReason::SourceEnded;
                    break 'read;
                }
            };

            if let Some(filter) = &filter {
                let keep = decode_frame(link, frame.data, frame.timestamp_ns, &local)
                    .is_ok_and(|meta: PacketMeta| filter.matches(&meta));
                if !keep {
                    filtered += 1;
                    self.progress
                        .packets_filtered
                        .store(filtered, Ordering::Relaxed);
                    continue;
                }
            }

            if let Err(e) = segment.write_packet(frame.timestamp_ns, frame.data, frame.original_len)
            {
                failure = Some(e);
                break 'read;
            }
            packets_total += 1;
            self.progress
                .packets_written
                .store(packets_total, Ordering::Relaxed);
            self.progress
                .bytes_written
                .store(written_total + segment.bytes(), Ordering::Relaxed);

            match self.spec.mode {
                RecordMode::Timed { max_bytes, .. } => {
                    if segment.bytes() >= max_bytes {
                        reason = StopReason::SizeLimit;
                        break 'read;
                    }
                }
                RecordMode::Ring {
                    max_total_bytes,
                    segment_bytes,
                } => {
                    if segment.bytes() >= segment_bytes {
                        // Roll: seal this segment, make room, open the next one.
                        let next = Segment::create(
                            &self.spec.dir,
                            &self.stem,
                            epoch_secs,
                            &mut seq,
                            link,
                            snaplen,
                            self.spec.interface_name.as_deref(),
                        );
                        let next = match next {
                            Ok(next) => next,
                            Err(e) => {
                                failure = Some(e);
                                break 'read;
                            }
                        };
                        let full = std::mem::replace(&mut segment, next);
                        match full.finalize() {
                            Ok((path, size)) => {
                                written_total += size;
                                finished_bytes += size;
                                finished.push_back(Finished { path, size });
                            }
                            Err(e) => {
                                failure = Some(e);
                                break 'read;
                            }
                        }
                        // Keep finished segments plus the new one within the total.
                        while finished_bytes + segment_bytes > max_total_bytes {
                            let Some(oldest) = finished.pop_front() else {
                                break;
                            };
                            finished_bytes -= oldest.size;
                            match fs::remove_file(&oldest.path) {
                                Ok(()) => deleted += 1,
                                Err(e) => tracing::warn!(
                                    path = %oldest.path.display(),
                                    error = %e,
                                    "could not delete an old ring segment"
                                ),
                            }
                        }
                    }
                }
            }
        }

        let kernel_drops = self.source.kernel_drops();

        // Seal the current segment. An empty ring segment is not worth keeping; a timed capture always
        // produces its (possibly empty but valid) file.
        let keep_current =
            segment.packets > 0 || matches!(self.spec.mode, RecordMode::Timed { .. });
        if keep_current {
            match segment.finalize() {
                Ok((path, size)) => {
                    written_total += size;
                    finished.push_back(Finished { path, size });
                }
                Err(e) => {
                    failure.get_or_insert(e);
                }
            }
        } else {
            segment.discard();
        }

        if let Some(e) = failure {
            return Err(e);
        }
        self.progress
            .bytes_written
            .store(written_total, Ordering::Relaxed);
        Ok(RecordingSummary {
            files: finished.into_iter().map(|f| f.path).collect(),
            packets_written: packets_total,
            bytes_written: written_total,
            packets_filtered: filtered,
            segments_deleted: deleted,
            kernel_drops,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{AfterScript, FakeSource, SyntheticConfig, SyntheticSource};
    use etherparse::PacketBuilder;
    use pcap_file::pcapng::{Block, PcapNgReader};

    fn udp_frame(src: [u8; 4], port: u16, payload: usize) -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4(src, [10, 0, 0, 5], 64)
            .udp(4000, port);
        let mut v = Vec::new();
        b.write(&mut v, &vec![0xAB; payload]).unwrap();
        v
    }

    struct Parsed {
        linktype: DataLink,
        snaplen: u32,
        resolution: InterfaceTsResolution,
        if_name: Option<String>,
        packets: Vec<(u64, u32, Vec<u8>)>, // timestamp ns, original len, data
    }

    fn parse(path: &Path) -> Parsed {
        let file = File::open(path).unwrap();
        let mut reader = PcapNgReader::new(file).unwrap();
        let mut parsed = Parsed {
            linktype: DataLink::ETHERNET,
            snaplen: 0,
            resolution: InterfaceTsResolution::MICRO,
            if_name: None,
            packets: Vec::new(),
        };
        while let Some(block) = reader.next_block() {
            match block.unwrap().0 {
                Block::InterfaceDescription(idb) => {
                    parsed.linktype = idb.linktype;
                    parsed.snaplen = idb.snaplen;
                    parsed.resolution = idb.ts_resolution();
                    for opt in &idb.options {
                        if let InterfaceDescriptionOption::IfName(n) = opt {
                            parsed.if_name = Some(n.to_string());
                        }
                    }
                }
                Block::EnhancedPacket(epb) => parsed.packets.push((
                    u64::try_from(epb.timestamp.as_nanos()).unwrap(),
                    epb.original_len,
                    epb.data.to_vec(),
                )),
                _ => {}
            }
        }
        parsed
    }

    fn script(count: usize, payload: usize) -> FakeSource {
        let mut src = FakeSource::new(LinkType::Ethernet);
        for i in 0..count {
            let frame = udp_frame([1, 1, 1, (i % 250) as u8 + 1], 53, payload);
            src.push_frame(1_700_000_000_000_000_000 + i as u64 * 1_234_567, &frame);
        }
        src
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn timed_capture_round_trips_with_exact_timestamps_and_headers_only_snaplen() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = RecordSpec::timed(dir.path(), "evidence", Duration::from_secs(60));
        spec.interface_name = Some("Ethernet0".into());
        let rec = Recorder::start(Box::new(script(10, 500)), spec).unwrap();
        let summary = rec.wait().unwrap();

        assert_eq!(summary.reason, StopReason::SourceEnded);
        assert_eq!(summary.packets_written, 10);
        assert_eq!(summary.files.len(), 1);
        let file = &summary.files[0];
        assert_eq!(file.extension().unwrap(), "pcapng");
        assert!(file
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("evidence-"));
        assert_eq!(fs::metadata(file).unwrap().len(), summary.bytes_written);
        assert_eq!(files_in(dir.path()).len(), 1, "no .partial left behind");

        let parsed = parse(file);
        assert_eq!(parsed.linktype, DataLink::ETHERNET);
        assert_eq!(parsed.snaplen, 128);
        assert_eq!(parsed.resolution, InterfaceTsResolution::NANO);
        assert_eq!(parsed.if_name.as_deref(), Some("Ethernet0"));
        assert_eq!(parsed.packets.len(), 10);
        let full_len = udp_frame([1, 1, 1, 1], 53, 500).len() as u32;
        for (i, (ts, orig, data)) in parsed.packets.iter().enumerate() {
            assert_eq!(*ts, 1_700_000_000_000_000_000 + i as u64 * 1_234_567);
            assert_eq!(*orig, full_len, "original length is preserved");
            assert_eq!(data.len(), 128, "only the headers are stored");
            assert_eq!(data[..14], [2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 8, 0]);
        }
    }

    #[test]
    fn full_payload_must_be_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = RecordSpec::timed(dir.path(), "full", Duration::from_secs(60));
        assert_eq!(spec.capture_opts().snaplen, 128);
        spec.payload = Payload::Full;
        assert_eq!(spec.capture_opts().snaplen, FULL_SNAPLEN);
        let summary = Recorder::start(Box::new(script(3, 900)), spec)
            .unwrap()
            .wait()
            .unwrap();
        let parsed = parse(&summary.files[0]);
        assert_eq!(parsed.snaplen, FULL_SNAPLEN);
        let full_len = udp_frame([1, 1, 1, 1], 53, 900).len();
        assert!(parsed.packets.iter().all(|(_, _, d)| d.len() == full_len));
    }

    #[test]
    fn custom_snaplen_is_clamped_and_applied() {
        assert_eq!(Payload::Headers { snaplen: 10 }.snaplen(), 64);
        assert_eq!(Payload::Headers { snaplen: 96 }.snaplen(), 96);
        let dir = tempfile::tempdir().unwrap();
        let mut spec = RecordSpec::timed(dir.path(), "snap", Duration::from_secs(60));
        spec.payload = Payload::Headers { snaplen: 96 };
        let summary = Recorder::start(Box::new(script(2, 500)), spec)
            .unwrap()
            .wait()
            .unwrap();
        let parsed = parse(&summary.files[0]);
        assert_eq!(parsed.snaplen, 96);
        assert!(parsed.packets.iter().all(|(_, _, d)| d.len() == 96));
    }

    #[test]
    fn raw_ip_sources_are_written_as_linktype_raw() {
        let dir = tempfile::tempdir().unwrap();
        let src = SyntheticSource::new(SyntheticConfig {
            total_packets: Some(5),
            ..SyntheticConfig::default()
        });
        let spec = RecordSpec::timed(dir.path(), "raw", Duration::from_secs(60));
        let summary = Recorder::start(Box::new(src), spec)
            .unwrap()
            .wait()
            .unwrap();
        let parsed = parse(&summary.files[0]);
        assert_eq!(parsed.linktype, DataLink::RAW);
        assert_eq!(u32::from(parsed.linktype), 101);
        assert_eq!(parsed.packets.len(), 5);
        assert_eq!(parsed.packets[0].2[0], 0x45);
    }

    #[test]
    fn the_filter_selects_what_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = FakeSource::new(LinkType::Ethernet);
        for i in 0..10u16 {
            src.push_frame(u64::from(i), &udp_frame([1, 1, 1, 1], 50 + i, 10));
        }
        src.push_frame(99, &[0xff; 6]); // garbage never matches a filter
        let mut spec = RecordSpec::timed(dir.path(), "f", Duration::from_secs(60));
        spec.filter = Some(Filter::parse("udp and dst port 52-54").unwrap());
        let summary = Recorder::start(Box::new(src), spec)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(summary.packets_written, 3);
        assert_eq!(summary.packets_filtered, 8);
        let parsed = parse(&summary.files[0]);
        let ts: Vec<u64> = parsed.packets.iter().map(|p| p.0).collect();
        assert_eq!(ts, [2, 3, 4]);
    }

    #[test]
    fn timed_capture_stops_at_its_duration() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = script(2, 10)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(5));
        src.push_timeout();
        let spec = RecordSpec::timed(dir.path(), "d", Duration::from_millis(150));
        let started = Instant::now();
        let summary = Recorder::start(Box::new(src), spec)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(summary.reason, StopReason::Duration);
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(parse(&summary.files[0]).packets.len(), 2);
    }

    #[test]
    fn timed_capture_stops_at_its_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = RecordSpec::timed(dir.path(), "s", Duration::from_secs(60));
        spec.mode = RecordMode::Timed {
            max_duration: Duration::from_secs(60),
            max_bytes: 4096,
        };
        let summary = Recorder::start(Box::new(script(1000, 300)), spec)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(summary.reason, StopReason::SizeLimit);
        assert!(summary.packets_written < 1000);
        let size = fs::metadata(&summary.files[0]).unwrap().len();
        assert!((4096..4096 + 512).contains(&size), "size {size}");
        assert_eq!(
            parse(&summary.files[0]).packets.len() as u64,
            summary.packets_written
        );
    }

    #[test]
    fn stop_finalizes_a_running_capture() {
        let dir = tempfile::tempdir().unwrap();
        let src = script(4, 10)
            .after_script(AfterScript::Idle)
            .with_read_timeout(Duration::from_millis(5));
        let spec = RecordSpec::timed(dir.path(), "live", Duration::from_secs(3600));
        let rec = Recorder::start(Box::new(src), spec).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while rec.progress().packets_written < 4 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(rec.is_running());
        let summary = rec.stop().unwrap();
        assert_eq!(summary.reason, StopReason::Requested);
        assert_eq!(parse(&summary.files[0]).packets.len(), 4);
        assert_eq!(files_in(dir.path()).len(), 1);
    }

    #[test]
    fn an_empty_timed_capture_is_still_a_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let spec = RecordSpec::timed(dir.path(), "empty", Duration::from_secs(60));
        let summary = Recorder::start(Box::new(FakeSource::new(LinkType::Ethernet)), spec)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(summary.packets_written, 0);
        assert_eq!(parse(&summary.files[0]).packets.len(), 0);
    }

    #[test]
    fn ring_buffer_keeps_the_total_bounded_and_deletes_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        // A file that is not ours must survive.
        fs::write(dir.path().join("keep-me.txt"), b"hello").unwrap();
        fs::write(
            dir.path().join("ring-0-0001.pcapng"),
            b"someone else's capture",
        )
        .unwrap();

        let mut spec = RecordSpec::ring(dir.path(), "ring");
        spec.mode = RecordMode::Ring {
            max_total_bytes: 20 * 1024,
            segment_bytes: 4 * 1024,
        };
        let count = 600;
        let summary = Recorder::start(Box::new(script(count, 100)), spec)
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(summary.reason, StopReason::SourceEnded);
        assert_eq!(summary.packets_written, count as u64);
        assert!(summary.segments_deleted > 0, "the ring wrapped");
        assert!(summary.bytes_written > 20 * 1024);

        let on_disk: u64 = summary
            .files
            .iter()
            .map(|f| fs::metadata(f).unwrap().len())
            .sum();
        assert!(on_disk <= 20 * 1024 + 1024, "ring holds {on_disk} bytes");
        assert!(summary.files.len() >= 3);
        // Foreign files untouched, no partials left.
        let names = files_in(dir.path());
        assert!(names.contains(&"keep-me.txt".to_owned()));
        assert!(names.contains(&"ring-0-0001.pcapng".to_owned()));
        assert!(names.iter().all(|n| !n.ends_with(".partial")));
        assert_eq!(names.len(), summary.files.len() + 2);

        // Every surviving segment parses, and together they are the newest packets in order.
        let mut stamps = Vec::new();
        for file in &summary.files {
            stamps.extend(parse(file).packets.iter().map(|p| p.0));
        }
        assert!(stamps.windows(2).all(|w| w[0] < w[1]));
        let last = 1_700_000_000_000_000_000 + (count as u64 - 1) * 1_234_567;
        assert_eq!(*stamps.last().unwrap(), last, "the newest packet is kept");
        assert!(stamps.len() < count, "the oldest were dropped");
    }

    #[test]
    fn a_ring_stopped_with_an_empty_segment_does_not_keep_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = RecordSpec::ring(dir.path(), "r");
        spec.mode = RecordMode::Ring {
            max_total_bytes: 8 * 1024,
            segment_bytes: 2 * 1024,
        };
        let summary = Recorder::start(Box::new(FakeSource::new(LinkType::Ethernet)), spec)
            .unwrap()
            .wait()
            .unwrap();
        assert!(summary.files.is_empty());
        assert!(files_in(dir.path()).is_empty());
    }

    #[test]
    fn writes_stay_inside_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let spec = RecordSpec::timed(dir.path(), "../../escape\\me/now", Duration::from_secs(60));
        let summary = Recorder::start(Box::new(script(1, 10)), spec)
            .unwrap()
            .wait()
            .unwrap();
        let file = &summary.files[0];
        assert_eq!(file.parent().unwrap(), dir.path());
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("______escape_me_now-"), "{name}");
        assert_eq!(sanitize(""), "capture");
        assert_eq!(sanitize(&"x".repeat(100)).len(), MAX_NAME_LEN);
    }

    #[test]
    fn two_recordings_never_share_a_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let run = || {
            let spec = RecordSpec::timed(dir.path(), "same", Duration::from_secs(60));
            Recorder::start(Box::new(script(1, 10)), spec)
                .unwrap()
                .wait()
                .unwrap()
        };
        let a = run();
        let b = run();
        assert_ne!(a.files[0], b.files[0]);
        assert!(a.files[0].exists() && b.files[0].exists());
    }

    #[test]
    fn invalid_settings_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let src = || Box::new(FakeSource::new(LinkType::Ethernet));
        let missing = dir.path().join("nope");
        let spec = RecordSpec::timed(&missing, "x", Duration::from_secs(1));
        assert!(matches!(
            Recorder::start(src(), spec),
            Err(CaptureError::InvalidSettings(_))
        ));
        let spec = RecordSpec::timed(dir.path(), "x", Duration::ZERO);
        assert!(matches!(
            Recorder::start(src(), spec),
            Err(CaptureError::InvalidSettings(_))
        ));
        let mut spec = RecordSpec::ring(dir.path(), "x");
        spec.mode = RecordMode::Ring {
            max_total_bytes: 3000,
            segment_bytes: 2000,
        };
        assert!(matches!(
            Recorder::start(src(), spec),
            Err(CaptureError::InvalidSettings(_))
        ));
        assert!(
            files_in(dir.path()).is_empty(),
            "nothing is created for a rejected spec"
        );
    }

    #[test]
    fn a_failing_source_still_finalizes_what_was_written_and_reports_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = script(3, 10);
        src.push_error("adapter vanished");
        let spec = RecordSpec::timed(dir.path(), "e", Duration::from_secs(60));
        let err = Recorder::start(Box::new(src), spec)
            .unwrap()
            .wait()
            .unwrap_err();
        assert!(matches!(err, CaptureError::Source(_)));
        let names = files_in(dir.path());
        assert_eq!(names.len(), 1);
        assert!(
            names[0].ends_with(".pcapng"),
            "the partial file was sealed: {names:?}"
        );
        assert_eq!(parse(&dir.path().join(&names[0])).packets.len(), 3);
    }
}
