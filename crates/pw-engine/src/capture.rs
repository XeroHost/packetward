// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Capture service (M4): the live capture that feeds the traffic statistics, timed/ring recordings
//! to `.pcapng`, and the explanation of which backend is in use. Wraps `pw-capture`.
//!
//! Everything platform specific is behind [`CaptureHost`], so the manager is tested with scripted
//! and synthetic sources.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pw_capture::{
    create_selected_backend, list_interfaces, select_system_backend, Availability, BackendKind,
    BackendSelection, BackendStatus, Capture, CaptureError, CaptureOpts, Filter, InterfaceInfo,
    PacketSource, Payload, PipelineConfig, RecordSpec, Recorder, RecordingSummary, StatsAggregator,
    StatsConfig, StatsHandle, StatsSnapshot, StopReason, SystemEnv, DEFAULT_SNAPLEN,
};
use pw_core::PacketMeta;
use pw_proto::{
    BackendKindView, BackendStatusView, CaptureCounters, CaptureFile, CaptureFiles, CaptureLive,
    CaptureRunState, CaptureSelection, CaptureStatus, ErrorCode, ErrorPayload, InterfaceView,
    MissingView, PayloadView, ProtocolRate, RateView, RecordModeView, RecordStartRequest,
    RecordingResult, RecordingView, TalkerView,
};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

/// Recordings older than this are deleted when the agent starts and when a recording starts.
pub const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_TIMED_SECS: u32 = 3600;
const GIB: u64 = 1 << 30;
/// All recordings together may take this much disk; the oldest finished ones are deleted to make room for a
/// new one. (Each recording is also bounded on its own: a timed one by size and time, a ring by its total.)
pub const RECORDINGS_MAX_TOTAL: u64 = 2 * GIB;
/// A recording does not start unless the disk keeps at least this much free besides the recording's own
/// maximum size: a capture must never be what fills the server's disk.
pub const MIN_FREE_BYTES: u64 = 2 * GIB;
const DEFAULT_TIMED_SECS: u32 = 60;
const MAX_FILTER_LEN: usize = 512;
/// Seconds of history the blind-capture check looks at.
const BLIND_WINDOW: usize = 10;
/// Outbound packets needed in the window before silence on the inbound side means something.
const BLIND_MIN_OUTBOUND: u64 = 20;
const LIVE_BACKLOG: usize = 16;

/// Called with every batch of decoded packets (the detection engine hooks in here). Must not block.
pub type PacketSink = Arc<dyn Fn(&[PacketMeta]) + Send + Sync>;

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_ms() -> u64 {
    now_ns() / 1_000_000
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

// ---- the machine behind the manager --------------------------------------------------------------

/// What the manager needs from the operating system.
pub trait CaptureHost: Send + Sync + 'static {
    fn selection(&self) -> BackendSelection;
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError>;
    fn open(
        &self,
        interface: &InterfaceInfo,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError>;
}

/// The real machine: Npcap if installed, else the Windows raw socket.
pub struct SystemCaptureHost;

impl CaptureHost for SystemCaptureHost {
    fn selection(&self) -> BackendSelection {
        select_system_backend()
    }

    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError> {
        list_interfaces()
    }

    fn open(
        &self,
        interface: &InterfaceInfo,
        opts: &CaptureOpts,
    ) -> Result<Box<dyn PacketSource>, CaptureError> {
        let selection = select_system_backend();
        create_selected_backend(&selection, &SystemEnv)?.open(&interface.id, opts)
    }
}

/// The adapter capture uses when none is chosen: the first one that is up, not loopback, with a
/// routable (not link-local) IPv4 address.
pub fn pick_default_interface(interfaces: &[InterfaceInfo]) -> Option<&InterfaceInfo> {
    interfaces.iter().find(|i| {
        i.up && !i.loopback
            && i.ipv4_addrs()
                .any(|a| !a.is_link_local() && !a.is_unspecified() && !a.is_loopback())
    })
}

// ---- blind detection ------------------------------------------------------------------------------

/// Notices a backend that sees what this machine sends but nothing it receives (the Windows
/// raw socket does this when the firewall drops the inbound copies).
#[derive(Debug, Default)]
pub struct BlindDetector {
    ring: [(u64, u64); BLIND_WINDOW],
    filled: usize,
    next: usize,
}

impl BlindDetector {
    /// Records one second of traffic.
    pub fn observe(&mut self, inbound_packets: u64, outbound_packets: u64) {
        self.ring[self.next] = (inbound_packets, outbound_packets);
        self.next = (self.next + 1) % BLIND_WINDOW;
        self.filled = (self.filled + 1).min(BLIND_WINDOW);
    }

    pub fn is_blind(&self) -> bool {
        if self.filled < BLIND_WINDOW {
            return false;
        }
        let inbound: u64 = self.ring.iter().map(|(i, _)| *i).sum();
        let outbound: u64 = self.ring.iter().map(|(_, o)| *o).sum();
        inbound == 0 && outbound >= BLIND_MIN_OUTBOUND
    }
}

// ---- manager --------------------------------------------------------------------------------------

struct Running {
    interface: InterfaceInfo,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    stats: StatsHandle,
}

struct RecordingState {
    view: RecordingView,
    recorder: Option<Recorder>,
}

struct Inner {
    state: CaptureRunState,
    error: Option<String>,
    running: Option<Running>,
    counters: CaptureCounters,
    blind: bool,
    recording: Option<RecordingState>,
}

pub struct CaptureManager {
    host: Arc<dyn CaptureHost>,
    dir: PathBuf,
    sink: Option<PacketSink>,
    inner: Arc<Mutex<Inner>>,
    live: broadcast::Sender<CaptureLive>,
}

impl CaptureManager {
    /// `dir` is where recordings are written; it is created (administrators only) on first use.
    pub fn new(host: Arc<dyn CaptureHost>, dir: PathBuf, sink: Option<PacketSink>) -> Self {
        Self {
            host,
            dir,
            sink,
            inner: Arc::new(Mutex::new(Inner {
                state: CaptureRunState::Stopped,
                error: None,
                running: None,
                counters: CaptureCounters::default(),
                blind: false,
                recording: None,
            })),
            live: broadcast::channel(LIVE_BACKLOG).0,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CaptureLive> {
        self.live.subscribe()
    }

    fn resolve_interface(&self, wanted: Option<&str>) -> Result<InterfaceInfo, ErrorPayload> {
        let interfaces = self
            .host
            .interfaces()
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))?;
        match wanted.map(str::trim).filter(|w| !w.is_empty()) {
            Some(text) => {
                let id = pw_capture::InterfaceId(text.to_owned());
                pw_capture::resolve_interface(&id, &pw_capture::StaticInterfaces(interfaces))
                    .map_err(|e| bad_request(e.to_string()))
            }
            None => pick_default_interface(&interfaces)
                .cloned()
                .ok_or_else(|| bad_request("no network adapter is up with an IPv4 address")),
        }
    }

    /// Starts the live capture. Starting an already running capture is a no-op.
    pub async fn start(&self, interface: Option<&str>) -> Result<(), ErrorPayload> {
        if lock(&self.inner).running.is_some() {
            return Ok(());
        }
        let selection = self.host.selection();
        if selection.selected.is_none() {
            return Err(bad_request(selection.summary));
        }
        let interface = self.resolve_interface(interface)?;
        let source = self
            .host
            .open(&interface, &CaptureOpts::default())
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))?;
        let (capture, batches) = Capture::start(source, PipelineConfig::default())
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))?;
        let stats = capture.stats_handle();
        let (stop_tx, stop_rx) = oneshot::channel();
        let sees_outbound = match selection.selected {
            Some(BackendKind::Npcap) => selection.npcap.caps.sees_outbound,
            _ => selection.raw_socket.caps.sees_outbound,
        };
        let task = tokio::spawn(run_live(
            capture,
            batches,
            stop_rx,
            Arc::clone(&self.inner),
            self.live.clone(),
            self.sink.clone(),
            stats.clone(),
            sees_outbound,
        ));
        let mut inner = lock(&self.inner);
        inner.state = CaptureRunState::Running;
        inner.error = None;
        inner.blind = false;
        inner.counters = CaptureCounters::default();
        inner.running = Some(Running {
            interface,
            stop: Some(stop_tx),
            task,
            stats,
        });
        Ok(())
    }

    /// Stops the live capture (and waits for its thread).
    pub async fn stop(&self) {
        let running = lock(&self.inner).running.take();
        if let Some(mut running) = running {
            if let Some(stop) = running.stop.take() {
                let _ = stop.send(());
            }
            let _ = running.task.await;
        }
        let mut inner = lock(&self.inner);
        if inner.state == CaptureRunState::Running {
            inner.state = CaptureRunState::Stopped;
        }
        inner.blind = false;
    }

    pub fn status(&self) -> CaptureStatus {
        let selection = selection_view(&self.host.selection());
        let interfaces = self
            .host
            .interfaces()
            .map(|list| list.iter().map(interface_view).collect())
            .unwrap_or_default();
        let mut inner = lock(&self.inner);
        if let Some(running) = &inner.running {
            let stats = running.stats.snapshot();
            inner.counters = CaptureCounters {
                received: stats.received,
                delivered: stats.delivered,
                dropped: stats.dropped_packets(),
            };
        }
        let recording = inner.recording.as_ref().map(|r| {
            let mut view = r.view.clone();
            if let Some(recorder) = &r.recorder {
                let progress = recorder.progress();
                view.packets_written = progress.packets_written;
                view.bytes_written = progress.bytes_written;
            }
            view
        });
        CaptureStatus {
            selection,
            state: inner.state,
            interface: inner.running.as_ref().map(|r| r.interface.name.clone()),
            error: inner.error.clone(),
            blind: inner.blind,
            counters: inner.counters,
            interfaces,
            recording,
            captures_dir: self.dir.display().to_string(),
        }
    }

    // ---- recordings --------------------------------------------------------------------------

    pub async fn record_start(&self, request: RecordStartRequest) -> Result<(), ErrorPayload> {
        if request.payload == PayloadView::Full && !request.confirm_full_payload {
            return Err(bad_request(
                "recording full packets captures the content of the traffic; confirm it explicitly",
            ));
        }
        let filter = match request
            .filter
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
        {
            Some(text) if text.len() > MAX_FILTER_LEN => {
                return Err(bad_request("the filter is too long"))
            }
            Some(text) => Some(Filter::parse(text).map_err(|e| bad_request(e.to_string()))?),
            None => None,
        };
        let duration_secs = match request.mode {
            RecordModeView::Timed => {
                let secs = request.duration_secs.unwrap_or(DEFAULT_TIMED_SECS);
                if !(1..=MAX_TIMED_SECS).contains(&secs) {
                    return Err(bad_request(format!(
                        "the duration must be between 1 and {MAX_TIMED_SECS} seconds"
                    )));
                }
                Some(secs)
            }
            RecordModeView::Ring => None,
        };
        if lock(&self.inner)
            .recording
            .as_ref()
            .is_some_and(|r| r.view.running)
        {
            return Err(ErrorPayload::new(
                ErrorCode::Busy,
                "a recording is already running",
            ));
        }
        // The same adapter as the live capture when it runs, the default one otherwise.
        let wanted = lock(&self.inner)
            .running
            .as_ref()
            .map(|r| r.interface.name.clone());
        let interface = self.resolve_interface(wanted.as_deref())?;
        ensure_private_dir(&self.dir)
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, format!("capture folder: {e}")))?;
        let removed = cleanup_old(&self.dir, RETENTION);
        if removed > 0 {
            tracing::info!(removed, "deleted old recordings");
        }
        // The most this recording can write, whatever the mode.
        let planned = match request.mode {
            RecordModeView::Timed => pw_capture::DEFAULT_TIMED_MAX_BYTES,
            RecordModeView::Ring => pw_capture::DEFAULT_RING_TOTAL_BYTES,
        };
        let dir = self.dir.clone();
        let dropped = make_room(
            &self.dir,
            planned,
            RECORDINGS_MAX_TOTAL,
            MIN_FREE_BYTES,
            move || crate::sys::free_disk_bytes(&dir),
        )
        .map_err(bad_request)?;
        if dropped > 0 {
            tracing::info!(
                dropped,
                "deleted the oldest recordings to stay within the folder budget"
            );
        }
        let payload = match request.payload {
            PayloadView::Headers => Payload::Headers {
                snaplen: DEFAULT_SNAPLEN,
            },
            PayloadView::Full => Payload::Full,
        };
        let mut spec = match request.mode {
            RecordModeView::Timed => RecordSpec::timed(
                &self.dir,
                &request.name,
                Duration::from_secs(u64::from(duration_secs.unwrap_or(DEFAULT_TIMED_SECS))),
            ),
            RecordModeView::Ring => RecordSpec::ring(&self.dir, &request.name),
        };
        spec.payload = payload;
        spec.filter = filter;
        spec.interface_name = Some(interface.name.clone());
        let source = self
            .host
            .open(&interface, &spec.capture_opts())
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))?;
        let recorder = Recorder::start(source, spec)
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))?;
        let view = RecordingView {
            running: true,
            name: sanitize_name(&request.name),
            mode: request.mode,
            payload: request.payload,
            filter: request.filter.filter(|f| !f.trim().is_empty()),
            started_unix_ms: unix_ms(),
            duration_secs,
            packets_written: 0,
            bytes_written: 0,
            result: None,
        };
        lock(&self.inner).recording = Some(RecordingState {
            view,
            recorder: Some(recorder),
        });
        tokio::spawn(watch_recording(Arc::clone(&self.inner)));
        Ok(())
    }

    /// Stops the running recording and waits for its files to be finalized.
    pub async fn record_stop(&self) -> Result<(), ErrorPayload> {
        let recorder = lock(&self.inner)
            .recording
            .as_mut()
            .and_then(|r| r.recorder.take());
        let Some(recorder) = recorder else {
            return Ok(()); // nothing running (or the watcher already collected it)
        };
        let outcome = tokio::task::spawn_blocking(move || recorder.stop())
            .await
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))?;
        finish_recording(&self.inner, outcome);
        Ok(())
    }

    pub fn files(&self) -> CaptureFiles {
        CaptureFiles {
            dir: self.dir.display().to_string(),
            files: list_captures(&self.dir),
        }
    }

    /// Deletes one finished capture file by name (never a path).
    pub fn delete_file(&self, name: &str) -> Result<(), ErrorPayload> {
        if name.contains(['/', '\\']) || name.contains("..") || !is_capture_name(name) {
            return Err(bad_request("not a capture file name"));
        }
        let running = lock(&self.inner)
            .recording
            .as_ref()
            .is_some_and(|r| r.view.running);
        if running {
            // A running recording owns its files; refuse rather than guess which ones.
            return Err(ErrorPayload::new(
                ErrorCode::Busy,
                "stop the recording before deleting files",
            ));
        }
        fs::remove_file(self.dir.join(name))
            .map_err(|e| ErrorPayload::new(ErrorCode::Internal, e.to_string()))
    }

    /// Deletes recordings older than the retention period. Returns how many files went.
    pub fn cleanup(&self) -> usize {
        cleanup_old(&self.dir, RETENTION)
    }
}

impl Drop for CaptureManager {
    fn drop(&mut self) {
        let mut inner = lock(&self.inner);
        if let Some(mut running) = inner.running.take() {
            if let Some(stop) = running.stop.take() {
                let _ = stop.send(());
            }
            running.task.abort();
        }
    }
}

// ---- background tasks -----------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_live(
    capture: Capture,
    mut batches: pw_capture::BatchReceiver,
    mut stop: oneshot::Receiver<()>,
    inner: Arc<Mutex<Inner>>,
    live: broadcast::Sender<CaptureLive>,
    sink: Option<PacketSink>,
    stats: StatsHandle,
    sees_outbound: bool,
) {
    let mut aggregator = StatsAggregator::new(StatsConfig::default(), now_ns());
    let mut blind = BlindDetector::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ended_by_source = false;
    loop {
        tokio::select! {
            batch = batches.recv() => match batch {
                Some(batch) => {
                    aggregator.observe_batch(&batch);
                    if let Some(sink) = &sink {
                        sink(&batch);
                    }
                }
                None => {
                    ended_by_source = true;
                    break;
                }
            },
            _ = ticker.tick() => {
                aggregator.set_dropped_total(stats.dropped_packets());
                let snapshot = aggregator.tick(now_ns());
                blind.observe(snapshot.inbound.packets, snapshot.outbound.packets);
                let is_blind = sees_outbound && blind.is_blind();
                {
                    let mut guard = lock(&inner);
                    guard.blind = is_blind;
                    let counters = stats.snapshot();
                    guard.counters = CaptureCounters {
                        received: counters.received,
                        delivered: counters.delivered,
                        dropped: counters.dropped_packets(),
                    };
                }
                let _ = live.send(live_view(&snapshot, is_blind));
            }
            _ = &mut stop => break,
        }
    }
    // The pipeline thread joins here, off the async workers.
    let outcome = tokio::task::spawn_blocking(move || capture.stop()).await;
    let mut guard = lock(&inner);
    match outcome {
        Ok(Ok(_)) if !ended_by_source => {}
        Ok(Ok(_)) => {
            guard.state = CaptureRunState::Stopped;
            guard.running = None;
        }
        Ok(Err(err)) => {
            guard.state = CaptureRunState::Failed;
            guard.error = Some(err.to_string());
            guard.running = None;
        }
        Err(err) => {
            guard.state = CaptureRunState::Failed;
            guard.error = Some(err.to_string());
            guard.running = None;
        }
    }
    guard.blind = false;
}

/// Collects a recording that ended by itself (duration or size reached, or its source failed).
async fn watch_recording(inner: Arc<Mutex<Inner>>) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let finished = {
            let guard = lock(&inner);
            match guard.recording.as_ref().and_then(|r| r.recorder.as_ref()) {
                Some(recorder) => !recorder.is_running(),
                None => return, // stopped by hand, `record_stop` collected it
            }
        };
        if finished {
            let recorder = lock(&inner)
                .recording
                .as_mut()
                .and_then(|r| r.recorder.take());
            if let Some(recorder) = recorder {
                let outcome = tokio::task::spawn_blocking(move || recorder.wait())
                    .await
                    .unwrap_or_else(|e| Err(CaptureError::Os(std::io::Error::other(e))));
                finish_recording(&inner, outcome);
            }
            return;
        }
    }
}

fn finish_recording(inner: &Mutex<Inner>, outcome: Result<RecordingSummary, CaptureError>) {
    let mut guard = lock(inner);
    let Some(state) = guard.recording.as_mut() else {
        return;
    };
    state.view.running = false;
    state.view.result = Some(match outcome {
        Ok(summary) => {
            state.view.packets_written = summary.packets_written;
            state.view.bytes_written = summary.bytes_written;
            RecordingResult {
                files: summary
                    .files
                    .iter()
                    .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .collect(),
                packets: summary.packets_written,
                bytes: summary.bytes_written,
                reason: match summary.reason {
                    StopReason::Requested => "requested",
                    StopReason::Duration => "duration",
                    StopReason::SizeLimit => "size_limit",
                    StopReason::SourceEnded => "source_ended",
                }
                .to_owned(),
                error: None,
            }
        }
        Err(err) => RecordingResult {
            files: Vec::new(),
            packets: state.view.packets_written,
            bytes: state.view.bytes_written,
            reason: "error".to_owned(),
            error: Some(err.to_string()),
        },
    });
}

// ---- views and files ------------------------------------------------------------------------------

fn kind_view(kind: BackendKind) -> BackendKindView {
    match kind {
        BackendKind::Npcap => BackendKindView::Npcap,
        BackendKind::RawSocket => BackendKindView::RawSocket,
    }
}

fn backend_view(status: &BackendStatus) -> BackendStatusView {
    BackendStatusView {
        kind: kind_view(status.kind),
        available: status.availability.is_available(),
        reason: match &status.availability {
            Availability::Unavailable { reason, .. } => Some(reason.clone()),
            _ => None,
        },
        sees_outbound: status.caps.sees_outbound,
        bpf: status.caps.bpf,
    }
}

fn selection_view(selection: &BackendSelection) -> CaptureSelection {
    CaptureSelection {
        selected: selection.selected.map(kind_view),
        npcap: backend_view(&selection.npcap),
        raw_socket: backend_view(&selection.raw_socket),
        missing: selection
            .missing
            .iter()
            .map(|m| MissingView {
                kind: format!("{:?}", m.kind).to_lowercase(),
                required: m.required,
                message: m.message.clone(),
                install_url: m.install_url.clone(),
            })
            .collect(),
        summary: selection.summary.clone(),
    }
}

fn interface_view(info: &InterfaceInfo) -> InterfaceView {
    InterfaceView {
        id: info.id.as_str().to_owned(),
        name: info.name.clone(),
        description: info.description.clone(),
        addrs: info.addrs.iter().map(ToString::to_string).collect(),
        up: info.up,
    }
}

fn live_view(snapshot: &StatsSnapshot, blind: bool) -> CaptureLive {
    let rate = |pps, bps| ProtocolRate {
        proto: String::new(),
        pps,
        bps,
    };
    let protocols = [
        ("tcp", &snapshot.tcp),
        ("udp", &snapshot.udp),
        ("icmp", &snapshot.icmp),
        ("other", &snapshot.other),
    ]
    .into_iter()
    .map(|(name, stats)| ProtocolRate {
        proto: name.to_owned(),
        ..rate(stats.pps, stats.bps)
    })
    .collect();
    CaptureLive {
        unix_ms: unix_ms(),
        blind,
        inbound: RateView {
            pps: snapshot.inbound.pps,
            bps: snapshot.inbound.bps,
        },
        outbound: RateView {
            pps: snapshot.outbound.pps,
            bps: snapshot.outbound.bps,
        },
        protocols,
        top_talkers: snapshot
            .top_talkers
            .iter()
            .map(|t| TalkerView {
                addr: t.ip.to_string(),
                packets: t.packets,
                bytes: t.bytes,
                tcp_packets: t.tcp_packets,
                udp_packets: t.udp_packets,
                icmp_packets: t.icmp_packets,
                other_packets: t.other_packets,
            })
            .collect(),
        dropped: snapshot.dropped_packets,
        untracked_packets: snapshot.untracked_packets,
    }
}

fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    if cleaned.is_empty() {
        "capture".to_owned()
    } else {
        cleaned
    }
}

fn is_capture_name(name: &str) -> bool {
    name.ends_with(".pcapng") && !name.starts_with('.')
}

fn modified_ms(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Finished `.pcapng` files of the capture folder, newest first. Foreign files are not listed.
pub fn list_captures(dir: &Path) -> Vec<CaptureFile> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<CaptureFile> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            (meta.is_file() && is_capture_name(&name)).then(|| CaptureFile {
                name,
                bytes: meta.len(),
                modified_unix_ms: modified_ms(&meta),
            })
        })
        .collect();
    files.sort_by_key(|f| std::cmp::Reverse(f.modified_unix_ms));
    files
}

/// Deletes `.pcapng` and orphan `.pcapng.partial` files older than `max_age`. Never touches anything
/// else in the folder. Returns how many files were removed.
pub fn cleanup_old(dir: &Path, max_age: Duration) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let now = SystemTime::now();
    let mut removed = 0;
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(is_capture_name(&name) || name.ends_with(".pcapng.partial")) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let old = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age > max_age);
        if meta.is_file() && old && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Makes sure a recording of at most `planned` bytes fits: the oldest finished recordings are deleted until
/// the folder (with the new one) stays within `cap`, then the disk must still have `planned + min_free` free
/// (`free` is asked after the deletions, because they free space). Returns how many files were deleted.
/// When the free space is unknown (`None`) only the folder cap applies. Only files this module made are
/// touched (`*.pcapng` and `*.pcapng.partial`), never anything else in the folder.
pub fn make_room(
    dir: &Path,
    planned: u64,
    cap: u64,
    min_free: u64,
    free: impl Fn() -> Option<u64>,
) -> Result<usize, String> {
    if planned > cap {
        return Err(format!(
            "a recording can take up to {} MiB but the recordings folder is limited to {} MiB",
            planned >> 20,
            cap >> 20
        ));
    }
    let mut files: Vec<(SystemTime, u64, PathBuf)> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    is_capture_name(&name) || name.ends_with(".pcapng.partial")
                })
                .filter_map(|e| {
                    let meta = e.metadata().ok()?;
                    meta.is_file()
                        .then(|| (meta.modified().unwrap_or(UNIX_EPOCH), meta.len(), e.path()))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort_by_key(|(modified, _, _)| *modified);
    let mut total: u64 = files.iter().map(|(_, len, _)| len).sum();
    let mut deleted = 0;
    for (_, len, path) in &files {
        if total + planned <= cap {
            break;
        }
        if fs::remove_file(path).is_ok() {
            total = total.saturating_sub(*len);
            deleted += 1;
        }
    }
    if total + planned > cap {
        return Err("the recordings folder is full and its files could not be removed".to_owned());
    }
    if let Some(free) = free() {
        if free < planned.saturating_add(min_free) {
            return Err(format!(
                "not enough free disk space for a recording: {} MiB free, at least {} MiB needed",
                free >> 20,
                planned.saturating_add(min_free) >> 20
            ));
        }
    }
    Ok(deleted)
}

/// Creates the folder and restricts it to administrators (and SYSTEM) where the OS supports it.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    crate::sys::protect_dir(dir)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use pw_capture::fake::{FakeSource, SyntheticConfig, SyntheticSource};
    use pw_capture::{BackendCaps, InterfaceId, LinkType, Missing, MissingKind};

    use super::*;

    fn caps(kind: BackendKind) -> BackendCaps {
        BackendCaps {
            kind,
            link_layer: false,
            bpf: false,
            sees_outbound: true,
            ipv6: false,
            needs_admin: true,
        }
    }

    pub(super) fn selection(selected: Option<BackendKind>) -> BackendSelection {
        let status = |kind, ok: bool| BackendStatus {
            kind,
            availability: if ok {
                Availability::Available
            } else {
                Availability::Unavailable {
                    reason: "not installed".into(),
                    install_url: Some("https://npcap.com".into()),
                }
            },
            caps: caps(kind),
        };
        BackendSelection {
            selected,
            npcap: status(BackendKind::Npcap, false),
            raw_socket: status(BackendKind::RawSocket, selected.is_some()),
            missing: vec![Missing {
                kind: MissingKind::Npcap,
                required: false,
                message: "Npcap improves capture".into(),
                install_url: Some("https://npcap.com".into()),
            }],
            summary: if selected.is_some() {
                "Using the Windows raw socket".into()
            } else {
                "No capture backend is available".into()
            },
        }
    }

    pub(super) fn adapter(name: &str, addr: &str, up: bool, loopback: bool) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId(format!("{{{name}}}")),
            name: name.into(),
            description: String::new(),
            addrs: vec![addr.parse::<IpAddr>().unwrap()],
            up,
            loopback,
        }
    }

    pub(super) type SourceFactory = dyn Fn() -> Box<dyn PacketSource> + Send + Sync;

    pub(super) struct FakeHost {
        pub(super) selection: BackendSelection,
        pub(super) interfaces: Vec<InterfaceInfo>,
        pub(super) source: Box<SourceFactory>,
    }

    impl CaptureHost for FakeHost {
        fn selection(&self) -> BackendSelection {
            self.selection.clone()
        }
        fn interfaces(&self) -> Result<Vec<InterfaceInfo>, CaptureError> {
            Ok(self.interfaces.clone())
        }
        fn open(
            &self,
            _: &InterfaceInfo,
            _: &CaptureOpts,
        ) -> Result<Box<dyn PacketSource>, CaptureError> {
            Ok((self.source)())
        }
    }

    pub(super) fn host(source: Box<SourceFactory>) -> Arc<FakeHost> {
        Arc::new(FakeHost {
            selection: selection(Some(BackendKind::RawSocket)),
            interfaces: vec![
                adapter("Loopback", "127.0.0.1", true, true),
                adapter("Ethernet", "10.0.0.5", true, false),
            ],
            source,
        })
    }

    fn synthetic(total: Option<u64>) -> Box<SourceFactory> {
        Box::new(move || {
            Box::new(SyntheticSource::new(SyntheticConfig {
                total_packets: total,
                rate_pps: 5000,
                paced: true,
                distinct_sources: 50,
                ..SyntheticConfig::default()
            }))
        })
    }

    pub(super) fn idle() -> Box<SourceFactory> {
        Box::new(|| {
            Box::new(
                FakeSource::new(LinkType::RawIp)
                    .after_script(pw_capture::fake::AfterScript::Idle)
                    .with_read_timeout(Duration::from_millis(20)),
            )
        })
    }

    pub(super) fn manager(host: Arc<FakeHost>) -> (CaptureManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            CaptureManager::new(host, dir.path().join("captures"), None),
            dir,
        )
    }

    #[test]
    fn the_default_adapter_is_up_not_loopback_and_has_a_routable_ipv4() {
        let list = vec![
            adapter("Loopback", "127.0.0.1", true, true),
            adapter("Down", "10.0.0.9", false, false),
            adapter("LinkLocal", "169.254.1.1", true, false),
            adapter("Ethernet", "10.0.0.5", true, false),
        ];
        assert_eq!(pick_default_interface(&list).unwrap().name, "Ethernet");
        assert!(pick_default_interface(&list[..3]).is_none());
    }

    #[test]
    fn blind_needs_a_full_window_of_outbound_only_traffic() {
        let mut detector = BlindDetector::default();
        for _ in 0..9 {
            detector.observe(0, 50);
        }
        assert!(!detector.is_blind(), "not enough history yet");
        detector.observe(0, 50);
        assert!(detector.is_blind());
        detector.observe(3, 50); // one inbound packet is enough to prove it sees inbound
        assert!(!detector.is_blind());
    }

    #[test]
    fn an_idle_machine_is_not_reported_blind() {
        let mut detector = BlindDetector::default();
        for _ in 0..20 {
            detector.observe(0, 1);
        }
        assert!(
            !detector.is_blind(),
            "almost no traffic at all proves nothing"
        );
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("my capture/../x"), "my_capture____x");
        assert_eq!(sanitize_name(""), "capture");
        assert_eq!(sanitize_name(&"a".repeat(200)).len(), 48);
    }

    #[tokio::test]
    async fn a_live_capture_publishes_stats_and_stops_cleanly() {
        let (manager, _dir) = manager(host(synthetic(None)));
        let mut live = manager.subscribe();
        manager.start(None).await.unwrap();
        let status = manager.status();
        assert_eq!(status.state, CaptureRunState::Running);
        assert_eq!(status.interface.as_deref(), Some("Ethernet"));

        let stats = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let stats = live.recv().await.unwrap();
                if stats.inbound.pps > 0 {
                    return stats;
                }
            }
        })
        .await
        .expect("stats within 5 s");
        assert!(!stats.top_talkers.is_empty());
        assert_eq!(stats.protocols.len(), 4);
        assert!(stats
            .protocols
            .iter()
            .any(|p| p.proto == "udp" && p.pps > 0));

        manager.start(None).await.unwrap(); // already running: no-op
        manager.stop().await;
        let status = manager.status();
        assert_eq!(status.state, CaptureRunState::Stopped);
        assert!(status.counters.received > 0);
    }

    #[tokio::test]
    async fn a_missing_backend_is_a_clear_error_not_a_crash() {
        let mut fake = host(idle());
        Arc::get_mut(&mut fake).unwrap().selection = selection(None);
        let (manager, _dir) = manager(fake);
        let err = manager.start(None).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("No capture backend"));
        let status = manager.status();
        assert_eq!(status.selection.selected, None);
        assert!(!status.selection.missing.is_empty());
        assert_eq!(status.state, CaptureRunState::Stopped);
    }

    #[tokio::test]
    async fn a_source_that_ends_marks_the_capture_stopped() {
        let (manager, _dir) = manager(host(synthetic(Some(500))));
        manager.start(None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while manager.status().state == CaptureRunState::Running {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the finite source ends");
        assert_eq!(manager.status().state, CaptureRunState::Stopped);
    }

    #[tokio::test]
    async fn an_unknown_adapter_is_rejected() {
        let (manager, _dir) = manager(host(idle()));
        let err = manager.start(Some("no-such-adapter")).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn the_packet_sink_sees_every_batch() {
        let seen = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counter = Arc::clone(&seen);
        let sink: PacketSink = Arc::new(move |batch| {
            counter.fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
        });
        let dir = tempfile::tempdir().unwrap();
        let manager =
            CaptureManager::new(host(synthetic(Some(400))), dir.path().join("c"), Some(sink));
        manager.start(None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while seen.load(std::sync::atomic::Ordering::Relaxed) < 400 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the sink receives all packets");
    }

    fn timed(name: &str, secs: u32) -> RecordStartRequest {
        RecordStartRequest {
            name: name.into(),
            mode: RecordModeView::Timed,
            duration_secs: Some(secs),
            filter: None,
            payload: PayloadView::Headers,
            confirm_full_payload: false,
        }
    }

    #[tokio::test]
    async fn a_timed_recording_ends_by_itself_and_leaves_a_pcapng() {
        let (manager, _dir) = manager(host(synthetic(None)));
        manager.record_start(timed("test run", 1)).await.unwrap();
        assert!(manager.status().recording.unwrap().running);
        let finished = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let recording = manager.status().recording.unwrap();
                if !recording.running {
                    return recording;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the timed recording ends");
        let result = finished.result.unwrap();
        assert_eq!(result.reason, "duration");
        assert!(result.packets > 0);
        assert_eq!(result.files.len(), 1);
        assert!(
            result.files[0].starts_with("test_run"),
            "{:?}",
            result.files
        );
        let files = manager.files().files;
        assert_eq!(files.len(), 1);
        assert!(files[0].bytes > 0);
        // Deleting by name works; a path does not.
        assert!(manager.delete_file("..\\x.pcapng").is_err());
        assert!(manager.delete_file("notes.txt").is_err());
        manager.delete_file(&files[0].name).unwrap();
        assert!(manager.files().files.is_empty());
    }

    #[tokio::test]
    async fn a_recording_can_be_stopped_and_only_one_runs_at_a_time() {
        let (manager, _dir) = manager(host(synthetic(None)));
        let ring = RecordStartRequest {
            mode: RecordModeView::Ring,
            duration_secs: None,
            ..timed("ring", 0)
        };
        manager.record_start(ring.clone()).await.unwrap();
        let busy = manager.record_start(ring).await.unwrap_err();
        assert_eq!(busy.code, ErrorCode::Busy);
        let delete_busy = manager.delete_file("x.pcapng").unwrap_err();
        assert_eq!(delete_busy.code, ErrorCode::Busy);
        tokio::time::sleep(Duration::from_millis(300)).await;
        manager.record_stop().await.unwrap();
        let recording = manager.status().recording.unwrap();
        assert!(!recording.running);
        assert_eq!(recording.result.unwrap().reason, "requested");
        manager.record_stop().await.unwrap(); // stopping again is harmless
    }

    #[tokio::test]
    async fn bad_recording_requests_are_rejected_before_anything_opens() {
        let (manager, dir) = manager(host(synthetic(None)));
        let full = RecordStartRequest {
            payload: PayloadView::Full,
            ..timed("x", 5)
        };
        let err = manager.record_start(full.clone()).await.unwrap_err();
        assert!(err.message.contains("confirm"));
        manager
            .record_start(RecordStartRequest {
                confirm_full_payload: true,
                ..full
            })
            .await
            .unwrap();
        manager.record_stop().await.unwrap();

        for (request, needle) in [
            (timed("x", 0), "duration"),
            (timed("x", 99_999), "duration"),
            (
                RecordStartRequest {
                    filter: Some("tcp and and".into()),
                    ..timed("x", 5)
                },
                "",
            ),
            (
                RecordStartRequest {
                    filter: Some("a".repeat(600)),
                    ..timed("x", 5)
                },
                "too long",
            ),
        ] {
            let err = manager.record_start(request).await.unwrap_err();
            assert_eq!(err.code, ErrorCode::BadRequest);
            assert!(err.message.contains(needle), "{}", err.message);
        }
        drop(dir);
    }

    #[tokio::test]
    async fn the_capture_api_works_over_the_ipc_protocol() {
        use pw_ipc::memory::memory_pair;
        use pw_ipc::{serve, Client, ClientError};
        use pw_netstat::fake::FakeNetStat;
        use pw_proto::{method, topic, CaptureStartRequest, ClientKind};

        let dir = tempfile::tempdir().unwrap();
        let mut config = crate::EngineConfig::new("1", false);
        config.capture_dir = dir.path().join("captures");
        let engine = Arc::new(crate::Engine::with_capture_host(
            config,
            Arc::new(FakeNetStat::new()),
            host(synthetic(None)),
            None,
        ));
        let (listener, connector) = memory_pair();
        tokio::spawn(serve(listener, engine, std::future::pending()));
        let client = Client::connect(connector.connect().await.unwrap(), ClientKind::Pwctl, "t")
            .await
            .unwrap();

        let status: CaptureStatus = client.request(method::CAPTURE_STATUS, &()).await.unwrap();
        assert_eq!(status.state, CaptureRunState::Stopped);
        assert_eq!(status.selection.selected, Some(BackendKindView::RawSocket));

        let mut stats = client.subscribe(topic::CAPTURE_STATS).await.unwrap();
        let status: CaptureStatus = client
            .request(method::CAPTURE_START, &CaptureStartRequest::default())
            .await
            .unwrap();
        assert_eq!(status.state, CaptureRunState::Running);
        let live = tokio::time::timeout(Duration::from_secs(5), stats.recv_as::<CaptureLive>())
            .await
            .expect("a stats message within 5 s")
            .unwrap();
        assert_eq!(live.protocols.len(), 4);

        // A bad request is a typed error, and a null payload for start means "defaults".
        let err = client
            .request::<_, CaptureStatus>(
                method::CAPTURE_RECORD_START,
                &serde_json::json!({"name": 5}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Remote(e) if e.code == ErrorCode::BadRequest));
        let status: CaptureStatus = client.request(method::CAPTURE_STOP, &()).await.unwrap();
        assert_eq!(status.state, CaptureRunState::Stopped);
        let files: CaptureFiles = client.request(method::CAPTURE_FILES, &()).await.unwrap();
        assert!(files.files.is_empty());
    }

    #[test]
    fn cleanup_only_removes_old_capture_files() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.pcapng", "b.pcapng.partial", "notes.txt", "c.pcapng"] {
            fs::write(dir.path().join(name), b"x").unwrap();
        }
        // Nothing is older than a week yet.
        assert_eq!(cleanup_old(dir.path(), RETENTION), 0);
        // Everything is older than zero seconds, but only capture files may go.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cleanup_old(dir.path(), Duration::ZERO), 3);
        assert!(dir.path().join("notes.txt").exists());
        assert_eq!(cleanup_old(&dir.path().join("missing"), Duration::ZERO), 0);
    }

    // ---- the disk budget -------------------------------------------------------------------

    const MIB: u64 = 1 << 20;

    fn file_of(dir: &Path, name: &str, mib: u64, age_secs: u64) {
        let path = dir.join(name);
        let file = fs::File::create(&path).unwrap();
        file.set_len(mib * MIB).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(age_secs))
            .unwrap();
    }

    #[test]
    fn the_oldest_recordings_go_first_until_the_new_one_fits_the_folder_budget() {
        let dir = tempfile::tempdir().unwrap();
        file_of(dir.path(), "old.pcapng", 400, 300);
        file_of(dir.path(), "mid.pcapng", 400, 200);
        file_of(dir.path(), "new.pcapng", 400, 100);
        file_of(dir.path(), "notes.txt", 400, 1_000);
        // Budget 1000 MiB, the new one may take 500: 1200 + 500 > 1000, so two files must go.
        let deleted = make_room(dir.path(), 500 * MIB, 1000 * MIB, 0, || None).unwrap();
        assert_eq!(deleted, 2);
        assert!(!dir.path().join("old.pcapng").exists());
        assert!(!dir.path().join("mid.pcapng").exists());
        assert!(dir.path().join("new.pcapng").exists());
        assert!(
            dir.path().join("notes.txt").exists(),
            "only recordings are ever deleted"
        );
    }

    #[test]
    fn a_recording_does_not_start_when_the_disk_would_be_left_too_full() {
        let dir = tempfile::tempdir().unwrap();
        let err = make_room(dir.path(), 500 * MIB, 2000 * MIB, 2000 * MIB, || {
            Some(2200 * MIB)
        })
        .unwrap_err();
        assert!(err.contains("not enough free disk space"), "{err}");
        // Enough room: fine. Unknown free space: only the folder budget applies.
        assert!(
            make_room(dir.path(), 500 * MIB, 2000 * MIB, 2000 * MIB, || Some(
                2600 * MIB
            ))
            .is_ok()
        );
        assert!(make_room(dir.path(), 500 * MIB, 2000 * MIB, 2000 * MIB, || None).is_ok());
    }

    #[test]
    fn the_free_space_is_asked_after_old_recordings_were_deleted() {
        let dir = tempfile::tempdir().unwrap();
        file_of(dir.path(), "a.pcapng", 900, 100);
        let path = dir.path().join("a.pcapng");
        // The disk reports little free space only while the old file still exists.
        let ok = make_room(dir.path(), 500 * MIB, 1000 * MIB, 100 * MIB, || {
            Some(if path.exists() { 50 * MIB } else { 5000 * MIB })
        });
        assert_eq!(ok, Ok(1));
    }

    #[test]
    fn a_recording_larger_than_the_whole_budget_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(make_room(dir.path(), 3000 * MIB, 2000 * MIB, 0, || None).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_reports_the_free_space_of_a_folder() {
        let free = crate::sys::free_disk_bytes(&std::env::temp_dir());
        assert!(free.is_some_and(|bytes| bytes > 0), "{free:?}");
        assert_eq!(
            crate::sys::free_disk_bytes(Path::new(r"Z:\no\such\folder")),
            None
        );
    }

    #[test]
    fn the_real_default_budget_holds_the_largest_recording() {
        const { assert!(RECORDINGS_MAX_TOTAL >= pw_capture::DEFAULT_TIMED_MAX_BYTES) };
        const { assert!(RECORDINGS_MAX_TOTAL >= pw_capture::DEFAULT_RING_TOTAL_BYTES) };
    }
}

/// Helpers other modules' tests use to get a capture manager without a machine behind it.
#[cfg(test)]
pub(crate) mod tests_support {
    use std::sync::Arc;

    use pw_proto::CaptureStatus;

    use super::tests::{adapter, host, idle, manager, selection, FakeHost};
    use super::{BackendKind, CaptureManager};

    /// A status whose adapters have exactly these addresses.
    pub fn status_with(addrs: &[&str]) -> CaptureStatus {
        let fake = Arc::new(FakeHost {
            selection: selection(Some(BackendKind::RawSocket)),
            interfaces: addrs
                .iter()
                .enumerate()
                .map(|(i, a)| adapter(&format!("eth{i}"), a, true, false))
                .collect(),
            source: idle(),
        });
        CaptureManager::new(fake, std::path::PathBuf::from("unused"), None).status()
    }

    /// A manager over a silent fake source; keep the returned directory alive.
    pub fn quiet_manager() -> (CaptureManager, tempfile::TempDir) {
        manager(host(idle()))
    }
}
