// SPDX-License-Identifier: GPL-3.0-or-later
//! Diagnostics service (M3): long jobs (ping, MTR) that stream progress on the `diag.progress` topic,
//! and short requests (DNS lookup, port check, local ports). Wraps `pw-diag`.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use pw_diag::mtr_adv::{
    export, is_public_ip, mtr_with, AdvHop, AdvMtrOptions, AdvMtrSnapshot, EnrichCache,
    HopEnricher, HopInfo, ModeUnavailable, MtrError, NoEnrich, PingerTransport, ProbeMode,
    ProbeReply, ProbeRequest, ProbeTransport, ReachKind, DEFAULT_TCP_PORT, DEFAULT_UDP_PORT,
};
use pw_diag::{
    format_report, mtr, ping, CancelToken, DiagError, DnsClient, DnsLookup, DnsOptions,
    DnsRecordType, EchoStatus, FnSink, HickoryBackend, HopSnapshot, MtrOptions, MtrSnapshot,
    NameCache, NoReverse, PingOptions, PingReply, PingSummary, Pinger, PortCheck, PortCheckLimiter,
    PortProtocol, PortState, ReportContext, ResolverChoice, RttSummary,
};
use pw_proto::{
    DiagEvent, DiagStartResponse, DnsErrorView, DnsLookupRequest, DnsLookupView, DnsRecordView,
    EchoOutcome, ErrorCode, ErrorPayload, LocalPort, LocalPorts, MtrExport, MtrExportFormat,
    MtrExportRequest, MtrHopView, MtrModeView, MtrReport, MtrStartRequest, MtrView, PingReplyView,
    PingStartRequest, PingSummaryView, PortCheckRequest, PortCheckView, PortStateView, Proto,
    RttView, TcpState,
};
use tokio::sync::{broadcast, mpsc};

use crate::intel::IntelApi;
use crate::poller::Snapshot;

/// Jobs that may run at the same time. A diagnostics tool must not become a traffic generator.
pub const MAX_RUNNING_JOBS: usize = 4;
/// Finished MTR jobs kept so their report can still be copied.
const KEEP_FINISHED: usize = 16;
const EVENT_BACKLOG: usize = 256;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

type BoxProbe<'a> = Pin<Box<dyn Future<Output = Result<ProbeReply, MtrError>> + Send + 'a>>;

/// Object-safe twin of [`ProbeTransport`] (whose `probe` returns `impl Future`), so the engine can
/// hold whichever transport it was built with without making `Diag` generic over it.
trait ErasedProbe: Send + Sync {
    fn erased_prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable>;
    fn erased_probe<'a>(&'a self, request: &'a ProbeRequest) -> BoxProbe<'a>;
}

impl<T: ProbeTransport> ErasedProbe for T {
    fn erased_prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable> {
        ProbeTransport::prepare(self, mode, target)
    }

    fn erased_probe<'a>(&'a self, request: &'a ProbeRequest) -> BoxProbe<'a> {
        Box::pin(ProbeTransport::probe(self, request))
    }
}

/// The probe transport of the engine, type-erased. Probes are a few per second, so the boxed
/// future per probe is irrelevant next to the network round trip.
pub struct SharedProbe(Arc<dyn ErasedProbe>);

impl SharedProbe {
    pub fn new<T: ProbeTransport + 'static>(transport: T) -> Self {
        Self(Arc::new(transport))
    }

    /// A transport the caller keeps a handle to (tests read the probes a fake received).
    pub fn shared<T: ProbeTransport + 'static>(transport: Arc<T>) -> Self {
        Self(transport)
    }

    /// ICMP only, through any [`Pinger`]: UDP and TCP report [`ModeUnavailable`].
    pub fn icmp<P: Pinger + 'static>(pinger: Arc<P>) -> Self {
        Self::new(PingerTransport::new(pinger))
    }
}

impl ProbeTransport for SharedProbe {
    fn prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable> {
        self.0.erased_prepare(mode, target)
    }

    async fn probe(&self, request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        self.0.erased_probe(request).await
    }
}

/// [`HopEnricher`] over the engine's intel service: the local GeoIP database only, public
/// addresses only. Nothing here can reach the network.
pub struct IntelEnricher(pub Arc<dyn IntelApi>);

impl HopEnricher for IntelEnricher {
    fn lookup(&self, ip: IpAddr) -> Option<HopInfo> {
        if !is_public_ip(ip) {
            return None;
        }
        self.0
            .lookup_one(ip)
            .map(|(asn, as_org, country_code)| HopInfo {
                asn,
                as_org,
                country_code,
            })
    }
}

/// Why a probe mode cannot run when `selection` has no capture backend, with what to do about it.
#[cfg(any(windows, test))]
fn capture_missing_reason(selection: &pw_capture::BackendSelection) -> Option<String> {
    selection.selected.is_none().then(|| {
        format!(
            "{}. Install Npcap from https://npcap.com or run the agent as administrator so the \
             built-in raw-socket backend can be used",
            selection.summary.trim_end_matches('.')
        )
    })
}

/// The transport of the real agent: ICMP through the Win32 helper API, UDP and TCP SYN through
/// sockets plus the capture backend chosen *when a trace starts* (so installing Npcap takes effect
/// without restarting the agent).
#[cfg(windows)]
pub struct SystemProbe {
    inner: pw_diag::mtr_adv::SystemProbeTransport,
}

#[cfg(windows)]
impl SystemProbe {
    pub fn new() -> Self {
        Self {
            inner: pw_diag::mtr_adv::SystemProbeTransport::new(Some(Arc::new(LazyBackend))),
        }
    }
}

#[cfg(windows)]
impl Default for SystemProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl ProbeTransport for SystemProbe {
    fn prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable> {
        if mode.needs_capture() {
            if let Some(reason) = capture_missing_reason(&pw_capture::select_system_backend()) {
                return Err(ModeUnavailable::new(mode, reason));
            }
        }
        self.inner.prepare(mode, target)
    }

    async fn probe(&self, request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        self.inner.probe(request).await
    }
}

/// A capture backend that picks Npcap or the raw-socket backend on every use.
#[cfg(windows)]
struct LazyBackend;

#[cfg(windows)]
impl pw_capture::CaptureBackend for LazyBackend {
    fn caps(&self) -> pw_capture::BackendCaps {
        match pw_capture::create_selected_backend(
            &pw_capture::select_system_backend(),
            &pw_capture::SystemEnv,
        ) {
            Ok(backend) => backend.caps(),
            Err(_) => pw_capture::BackendCaps {
                kind: pw_capture::BackendKind::RawSocket,
                link_layer: false,
                bpf: false,
                sees_outbound: false,
                ipv6: false,
                needs_admin: true,
            },
        }
    }

    fn open(
        &self,
        interface: &pw_capture::InterfaceId,
        opts: &pw_capture::CaptureOpts,
    ) -> Result<Box<dyn pw_capture::PacketSource>, pw_capture::CaptureError> {
        pw_capture::create_selected_backend(
            &pw_capture::select_system_backend(),
            &pw_capture::SystemEnv,
        )?
        .open(interface, opts)
    }
}

/// The latest table of an MTR job, in the advanced shape (which also holds simple-path jobs).
struct LastMtr {
    snapshot: AdvMtrSnapshot,
    /// Started with advanced options: `diag.mtr.report` then renders the advanced report.
    advanced: bool,
}

struct Job {
    cancel: CancelToken,
    running: bool,
    target_text: String,
    last_mtr: Option<LastMtr>,
}

#[derive(Default)]
struct Jobs {
    map: HashMap<u64, Job>,
    finished: VecDeque<u64>,
}

pub struct Diag<P> {
    pinger: Arc<P>,
    probe: Arc<SharedProbe>,
    enricher: Arc<dyn HopEnricher>,
    jobs: Arc<Mutex<Jobs>>,
    next_id: AtomicU64,
    events: broadcast::Sender<DiagEvent>,
    limiter: PortCheckLimiter,
    names: Option<Arc<NameCache<DnsClient<HickoryBackend>>>>,
}

/// An MTR request after validation: which engine runs it.
enum MtrPlan {
    /// Plain ICMP through the pinger (the default case).
    Simple(MtrOptions),
    /// Another mode, port, interval or address family: through `mtr_adv::mtr_with`.
    Advanced(AdvMtrOptions),
}

/// `true` when the request needs the advanced engine: a probe mode other than ICMP, or any of the
/// options only that engine honours (port, interval, address family). Packet size and hop limit
/// are honoured by both.
fn is_advanced(request: &MtrStartRequest) -> bool {
    request.mode.is_some_and(|mode| mode != MtrModeView::Icmp)
        || request.port.is_some()
        || request.interval_ms.is_some()
        || request.prefer_ipv6 == Some(true)
}

fn probe_mode(request: &MtrStartRequest) -> ProbeMode {
    match request.mode.unwrap_or_default() {
        MtrModeView::Icmp => ProbeMode::Icmp,
        MtrModeView::Udp => ProbeMode::Udp,
        MtrModeView::Tcp => ProbeMode::TcpSyn {
            port: request.port.unwrap_or(DEFAULT_TCP_PORT),
        },
    }
}

fn plan(request: &MtrStartRequest) -> Result<MtrPlan, ErrorPayload> {
    if !is_advanced(request) {
        let mut options = MtrOptions::default();
        if let Some(cycles) = request.cycles {
            options.cycles = cycles;
        }
        if let Some(hops) = request.max_hops {
            options.max_hops = hops;
        }
        if let Some(ms) = request.timeout_ms {
            options.timeout = Duration::from_millis(u64::from(ms));
        }
        if let Some(size) = request.packet_size {
            options.packet_size = size;
        }
        return Ok(MtrPlan::Simple(options));
    }
    let mut options = AdvMtrOptions {
        mode: probe_mode(request),
        udp_port: request.port.unwrap_or(DEFAULT_UDP_PORT),
        resolve_names: request.resolve_names.unwrap_or(true),
        ..AdvMtrOptions::default()
    };
    if let Some(cycles) = request.cycles {
        options.cycles = cycles;
    }
    if let Some(hops) = request.max_hops {
        options.max_hops = hops;
    }
    if let Some(ms) = request.timeout_ms {
        options.timeout = Duration::from_millis(u64::from(ms));
    }
    if let Some(size) = request.packet_size {
        options.packet_size = size;
    }
    if let Some(ms) = request.interval_ms {
        options.interval = Duration::from_millis(u64::from(ms));
    }
    options.validate().map_err(|err| mtr_error_payload(&err))?;
    Ok(MtrPlan::Advanced(options))
}

fn mtr_error_payload(err: &MtrError) -> ErrorPayload {
    match err {
        MtrError::ModeUnavailable(unavailable) => {
            ErrorPayload::new(ErrorCode::ModeUnavailable, unavailable.to_string())
        }
        MtrError::Diag(DiagError::InvalidInput(message)) => bad_request(message.clone()),
        MtrError::Diag(other) => ErrorPayload::new(ErrorCode::Internal, other.to_string()),
    }
}

impl<P: Pinger + 'static> Diag<P> {
    /// ICMP only (UDP and TCP MTR report `ModeUnavailable`) and no ASN / country lookups.
    pub fn new(pinger: Arc<P>) -> Self {
        let probe = SharedProbe::icmp(Arc::clone(&pinger));
        Self::with_parts(pinger, probe, Arc::new(NoEnrich))
    }

    /// `probe` sends the advanced MTR's probes; `enricher` adds ASN / country to hops (it must be a
    /// local lookup, see [`HopEnricher`]).
    pub fn with_parts(pinger: Arc<P>, probe: SharedProbe, enricher: Arc<dyn HopEnricher>) -> Self {
        // Reverse lookups of hop addresses go to the system resolver only (never a third party).
        let names = DnsClient::with_options(&DnsOptions::default())
            .ok()
            .map(|client| Arc::new(NameCache::new(Arc::new(client), Duration::from_secs(2))));
        Self {
            pinger,
            probe: Arc::new(probe),
            enricher,
            jobs: Arc::new(Mutex::new(Jobs::default())),
            next_id: AtomicU64::new(1),
            events: broadcast::channel(EVENT_BACKLOG).0,
            limiter: PortCheckLimiter::new(8),
            names,
        }
    }

    /// Events of every job, for a `diag.progress` subscriber. Each subscriber sees all jobs; the
    /// client filters by `job_id`. A subscriber that falls behind skips events instead of stalling.
    pub fn subscribe(&self) -> mpsc::Receiver<serde_json::Value> {
        let (out, rx) = mpsc::channel(32);
        let mut events = self.events.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        let Ok(value) = serde_json::to_value(&event) else {
                            continue;
                        };
                        if out.send(value).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        rx
    }

    fn register(&self, target_text: &str) -> Result<(u64, CancelToken), ErrorPayload> {
        let mut jobs = lock(&self.jobs);
        if jobs.map.values().filter(|job| job.running).count() >= MAX_RUNNING_JOBS {
            return Err(ErrorPayload::new(
                ErrorCode::Busy,
                format!("{MAX_RUNNING_JOBS} diagnostics are already running; wait or cancel one"),
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let cancel = CancelToken::new();
        jobs.map.insert(
            id,
            Job {
                cancel: cancel.clone(),
                running: true,
                target_text: target_text.to_owned(),
                last_mtr: None,
            },
        );
        Ok((id, cancel))
    }

    fn finish(jobs: &Mutex<Jobs>, id: u64) {
        let mut jobs = lock(jobs);
        if let Some(job) = jobs.map.get_mut(&id) {
            job.running = false;
        }
        jobs.finished.push_back(id);
        while jobs.finished.len() > KEEP_FINISHED {
            if let Some(old) = jobs.finished.pop_front() {
                jobs.map.remove(&old);
            }
        }
    }

    pub async fn start_ping(
        &self,
        request: PingStartRequest,
    ) -> Result<DiagStartResponse, ErrorPayload> {
        let target = resolve_target(&request.target).await?;
        let mut options = PingOptions::default();
        if let Some(count) = request.count {
            options.count = count;
        }
        if let Some(ms) = request.timeout_ms {
            options.timeout = Duration::from_millis(u64::from(ms));
        }
        if let Some(size) = request.packet_size {
            options.packet_size = size;
        }
        let (id, cancel) = self.register(&request.target)?;
        let pinger = Arc::clone(&self.pinger);
        let events = self.events.clone();
        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(async move {
            let replies = events.clone();
            let mut sink = FnSink(move |reply: PingReply| {
                let _ = replies.send(DiagEvent::PingReply {
                    job_id: id,
                    reply: ping_reply_view(&reply),
                });
            });
            let summary = ping(&*pinger, target, &options, &cancel, &mut sink).await;
            let _ = events.send(DiagEvent::PingDone {
                job_id: id,
                summary: ping_summary_view(&summary),
            });
            Self::finish(&jobs, id);
        });
        Ok(DiagStartResponse {
            job_id: id,
            target_ip: target.to_string(),
        })
    }

    pub async fn start_mtr(
        &self,
        request: MtrStartRequest,
    ) -> Result<DiagStartResponse, ErrorPayload> {
        let plan = plan(&request)?;
        let target =
            resolve_target_pref(&request.target, request.prefer_ipv6 == Some(true)).await?;
        // A mode that cannot run here is refused now, as a typed error, instead of failing the job
        // later. Preparing may open the capture interface, which blocks.
        if let MtrPlan::Advanced(options) = &plan {
            let probe = Arc::clone(&self.probe);
            let mode = options.mode;
            tokio::task::spawn_blocking(move || ProbeTransport::prepare(&*probe, mode, target))
                .await
                .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string()))?
                .map_err(|unavailable| mtr_error_payload(&MtrError::from(unavailable)))?;
        }
        let resolve_names = request.resolve_names.unwrap_or(true);
        let (id, cancel) = self.register(&request.target)?;
        let pinger = Arc::clone(&self.pinger);
        let probe = Arc::clone(&self.probe);
        let events = self.events.clone();
        let jobs = Arc::clone(&self.jobs);
        let names = self.names.clone().filter(|_| resolve_names);
        // One cache per job: "no data" answers are remembered, so a GeoIP database downloaded later
        // must not be hidden behind an older job's misses.
        let enrich = Arc::new(EnrichCache::new(Arc::clone(&self.enricher)));
        tokio::spawn(async move {
            let outcome: Result<bool, MtrError> = match plan {
                MtrPlan::Simple(options) => {
                    let (store, snapshots, cache) =
                        (Arc::clone(&jobs), events.clone(), Arc::clone(&enrich));
                    let mut sink = FnSink(move |snapshot: MtrSnapshot| {
                        let adv = adv_from_simple(&snapshot, &cache);
                        record_snapshot(&store, &snapshots, id, adv, false);
                    });
                    let run = match &names {
                        Some(names) => {
                            mtr(pinger, target, &options, names, &cancel, &mut sink).await
                        }
                        None => {
                            mtr(
                                pinger,
                                target,
                                &options,
                                &NameCache::<NoReverse>::disabled(),
                                &cancel,
                                &mut sink,
                            )
                            .await
                        }
                    };
                    run.map(|last| last.cancelled).map_err(MtrError::from)
                }
                MtrPlan::Advanced(options) => {
                    let (store, snapshots) = (Arc::clone(&jobs), events.clone());
                    let mut sink = FnSink(move |snapshot: AdvMtrSnapshot| {
                        record_snapshot(&store, &snapshots, id, snapshot, true);
                    });
                    let run = match &names {
                        Some(names) => {
                            mtr_with(probe, target, &options, names, &enrich, &cancel, &mut sink)
                                .await
                        }
                        None => {
                            mtr_with(
                                probe,
                                target,
                                &options,
                                &NameCache::<NoReverse>::disabled(),
                                &enrich,
                                &cancel,
                                &mut sink,
                            )
                            .await
                        }
                    };
                    run.map(|last| last.cancelled)
                }
            };
            match outcome {
                Ok(cancelled) => {
                    let _ = events.send(DiagEvent::MtrDone {
                        job_id: id,
                        cancelled,
                    });
                }
                Err(err) => {
                    let _ = events.send(DiagEvent::Failed {
                        job_id: id,
                        message: err.to_string(),
                    });
                }
            }
            Self::finish(&jobs, id);
        });
        Ok(DiagStartResponse {
            job_id: id,
            target_ip: target.to_string(),
        })
    }

    /// Asks a running job to stop. Cancelling a finished or unknown job is not an error.
    pub fn cancel(&self, job_id: u64) {
        if let Some(job) = lock(&self.jobs).map.get(&job_id) {
            job.cancel.cancel();
        }
    }

    /// The plain-text report of the latest snapshot of an MTR job. `source_public_ip` is the machine's
    /// public address when a XeroHost node told us; the line is omitted otherwise. Jobs started with
    /// the default options keep the simple report; the others get the advanced one (mode, ASN, country).
    pub fn mtr_report(
        &self,
        job_id: u64,
        source_public_ip: Option<IpAddr>,
    ) -> Result<MtrReport, ErrorPayload> {
        let jobs = lock(&self.jobs);
        let job = jobs
            .map
            .get(&job_id)
            .ok_or_else(|| bad_request("unknown diagnostics job"))?;
        let last = job
            .last_mtr
            .as_ref()
            .ok_or_else(|| bad_request("this job has no MTR data yet"))?;
        let context = ReportContext {
            source_public_ip,
            generated_at: SystemTime::now(),
            target: job.target_text.clone(),
        };
        let text = if last.advanced {
            export::support_report(&last.snapshot, &context)
        } else {
            format_report(&last.snapshot.to_trace(), &context)
        };
        Ok(MtrReport { text })
    }

    /// The latest snapshot of an MTR job rendered as CSV, JSON or the support text, with a file name
    /// that is safe on Windows. `request.source_ip` fills the "source public IP" line when given.
    pub fn mtr_export(&self, request: &MtrExportRequest) -> Result<MtrExport, ErrorPayload> {
        let source_public_ip = match request.source_ip.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(text) => Some(
                text.parse::<IpAddr>()
                    .map_err(|_| bad_request("the source IP is not a valid address"))?,
            ),
        };
        let jobs = lock(&self.jobs);
        let job = jobs
            .map
            .get(&request.job_id)
            .ok_or_else(|| bad_request("unknown diagnostics job"))?;
        let last = job
            .last_mtr
            .as_ref()
            .ok_or_else(|| bad_request("this job has no MTR data yet"))?;
        let now = SystemTime::now();
        let context = ReportContext {
            source_public_ip,
            generated_at: now,
            target: job.target_text.clone(),
        };
        let (content, extension) = match request.format {
            MtrExportFormat::Csv => (export::to_csv(&last.snapshot), "csv"),
            MtrExportFormat::Json => (export::to_json(&last.snapshot, &context), "json"),
            MtrExportFormat::Text => (export::support_report(&last.snapshot, &context), "txt"),
        };
        Ok(MtrExport {
            format: request.format,
            filename: export_filename(&job.target_text, now, extension),
            content,
        })
    }

    pub async fn dns_lookup(
        &self,
        request: DnsLookupRequest,
    ) -> Result<DnsLookupView, ErrorPayload> {
        let record_type: DnsRecordType = request
            .record_type
            .parse()
            .map_err(|_| bad_request(format!("unknown record type {:?}", request.record_type)))?;
        let resolver = match request.resolver.as_str() {
            "system" | "" => ResolverChoice::System,
            "cloudflare" => ResolverChoice::Cloudflare,
            "google" => ResolverChoice::Google,
            "custom" => {
                let servers: Result<Vec<IpAddr>, _> = request
                    .custom_servers
                    .iter()
                    .map(|s| s.trim().parse::<IpAddr>())
                    .collect();
                let servers =
                    servers.map_err(|_| bad_request("custom DNS servers must be IP addresses"))?;
                if servers.is_empty() {
                    return Err(bad_request("add at least one custom DNS server"));
                }
                ResolverChoice::Custom(servers)
            }
            other => return Err(bad_request(format!("unknown resolver {other:?}"))),
        };
        let client = DnsClient::with_options(&DnsOptions {
            resolver,
            ..DnsOptions::default()
        })
        .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string()))?;
        let lookup = client
            .lookup(&request.name, record_type)
            .await
            .map_err(|err| bad_request(err.to_string()))?;
        Ok(dns_view(&lookup))
    }

    pub async fn port_check(
        &self,
        request: PortCheckRequest,
    ) -> Result<PortCheckView, ErrorPayload> {
        let timeout = Duration::from_millis(u64::from(request.timeout_ms.unwrap_or(3000)));
        let check = match request.protocol.as_str() {
            "tcp" => {
                self.limiter
                    .tcp_connect(&request.host, request.port, timeout)
                    .await
            }
            "udp" => {
                self.limiter
                    .udp_check(&request.host, request.port, timeout)
                    .await
            }
            other => return Err(bad_request(format!("unknown protocol {other:?}"))),
        }
        .map_err(|err| bad_request(err.to_string()))?;
        Ok(port_view(&check))
    }
}

/// Listening sockets from the latest network snapshot (TCP listeners and UDP endpoints), with
/// their owning process. The engine's netstat data is the source: nothing is probed.
pub fn local_ports(snapshot: Option<&Snapshot>) -> LocalPorts {
    let Some(snapshot) = snapshot else {
        return LocalPorts::default();
    };
    let table = &snapshot.table;
    let mut ports: Vec<LocalPort> = table
        .rows
        .iter()
        .filter(|row| row.proto == Proto::Udp || row.state == Some(TcpState::Listen))
        .map(|row| LocalPort {
            proto: row.proto,
            addr: row.local_addr.clone(),
            port: row.local_port,
            pid: row.pid,
            process: table.processes.get(&row.pid).cloned(),
        })
        .collect();
    ports.sort_by(|a, b| (a.proto as u8, a.port, &a.addr).cmp(&(b.proto as u8, b.port, &b.addr)));
    LocalPorts { ports }
}

/// A target typed by the user: an address, or a host name resolved here (IPv4 preferred).
pub async fn resolve_target(text: &str) -> Result<IpAddr, ErrorPayload> {
    resolve_target_pref(text, false).await
}

/// [`resolve_target`] with the address family preference: `prefer_ipv6` picks an IPv6 address of a
/// host name when it has one (and falls back to IPv4 otherwise).
pub async fn resolve_target_pref(text: &str, prefer_ipv6: bool) -> Result<IpAddr, ErrorPayload> {
    let text = text.trim();
    if text.is_empty() {
        return Err(bad_request("enter a host name or an IP address"));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(ip.to_canonical());
    }
    if text.len() > 253
        || !text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(bad_request("that is not a valid host name"));
    }
    let lookup = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((text, 0))).await;
    let addrs: Vec<IpAddr> = match lookup {
        Ok(Ok(found)) => found.map(|a| a.ip().to_canonical()).collect(),
        Ok(Err(err)) => return Err(bad_request(format!("could not resolve {text}: {err}"))),
        Err(_) => return Err(bad_request(format!("resolving {text} timed out"))),
    };
    addrs
        .iter()
        .find(|ip| ip.is_ipv6() == prefer_ipv6)
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| bad_request(format!("{text} has no address")))
}

// ---- conversions to the wire types (pure, tested) ------------------------------------------------

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn rtt_view(rtt: &RttSummary) -> RttView {
    RttView {
        count: rtt.count,
        last_ms: rtt.last_ms,
        min_ms: rtt.min_ms,
        avg_ms: rtt.avg_ms,
        max_ms: rtt.max_ms,
        stddev_ms: rtt.stddev_ms,
        jitter_ms: rtt.jitter_ms,
    }
}

pub fn ping_reply_view(reply: &PingReply) -> PingReplyView {
    PingReplyView {
        seq: reply.seq,
        outcome: match reply.status {
            EchoStatus::Success => EchoOutcome::Success,
            EchoStatus::TtlExpired => EchoOutcome::TtlExpired,
            EchoStatus::Unreachable => EchoOutcome::Unreachable,
            EchoStatus::TimedOut => EchoOutcome::TimedOut,
            EchoStatus::Other(_) => EchoOutcome::Other,
        },
        from: reply.from.map(|ip| ip.to_string()),
        rtt_ms: reply.rtt.map(ms),
        ttl: reply.ttl,
        bytes: reply.bytes,
        error: reply.error.clone(),
    }
}

pub fn ping_summary_view(summary: &PingSummary) -> PingSummaryView {
    PingSummaryView {
        target: summary.target.to_string(),
        sent: summary.sent,
        received: summary.received,
        loss_percent: summary.loss_percent,
        rtt: summary.rtt.as_ref().map(rtt_view),
        cancelled: summary.cancelled,
    }
}

/// The advanced table of a simple-path snapshot (ICMP, no port), with ASN / country per hop.
fn adv_from_simple<E: HopEnricher>(
    snapshot: &MtrSnapshot,
    enrich: &EnrichCache<E>,
) -> AdvMtrSnapshot {
    AdvMtrSnapshot {
        mode: ProbeMode::Icmp,
        port: 0,
        target: snapshot.target,
        cycle: snapshot.cycle,
        total_cycles: snapshot.total_cycles,
        hops: snapshot
            .hops
            .iter()
            .map(|hop| AdvHop {
                info: hop.addr.and_then(|addr| enrich.info(addr)),
                hop: hop.clone(),
            })
            .collect(),
        destination_reached: snapshot.destination_reached,
        reached_via: snapshot.destination_reached.then_some(ReachKind::EchoReply),
        cancelled: snapshot.cancelled,
    }
}

/// Keeps `snapshot` as the job's latest table and publishes it on the progress topic.
fn record_snapshot(
    jobs: &Mutex<Jobs>,
    events: &broadcast::Sender<DiagEvent>,
    job_id: u64,
    snapshot: AdvMtrSnapshot,
    advanced: bool,
) {
    let view = adv_view(&snapshot);
    if let Some(job) = lock(jobs).map.get_mut(&job_id) {
        job.last_mtr = Some(LastMtr { snapshot, advanced });
    }
    let _ = events.send(DiagEvent::MtrSnapshot {
        job_id,
        snapshot: view,
    });
}

/// `packetward-mtr-<target>-<UTC stamp>.<extension>`: the target keeps letters, digits, `.`, `-`
/// and `_` (IPv6 colons and anything else a Windows file name refuses become `_`), at most 48 chars.
fn export_filename(target: &str, at: SystemTime, extension: &str) -> String {
    let safe: String = target
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    let safe = safe.trim_matches(|c| c == '.' || c == '_');
    let safe = if safe.is_empty() { "target" } else { safe };
    let stamp = pw_diag::format_utc(at)
        .trim_end_matches(" UTC")
        .replace(['-', ':'], "")
        .replace(' ', "-");
    format!("packetward-mtr-{safe}-{stamp}.{extension}")
}

fn hop_view(hop: &HopSnapshot) -> MtrHopView {
    MtrHopView {
        ttl: hop.ttl,
        addr: hop.addr.map(|ip| ip.to_string()),
        other_addrs: hop.other_addrs.iter().map(ToString::to_string).collect(),
        name: hop.name.clone(),
        sent: hop.sent,
        received: hop.received,
        loss_percent: hop.loss_percent,
        rtt: hop.rtt.as_ref().map(rtt_view),
        address_changes: hop.address_changes,
        asn: None,
        as_org: None,
        country: None,
    }
}

/// The wire view of an advanced table: the simple one plus mode, port, how the destination
/// answered and ASN / country per hop.
pub fn adv_view(snapshot: &AdvMtrSnapshot) -> MtrView {
    let trace = snapshot.to_trace();
    let mut view = mtr_view(&trace);
    for (view_hop, hop) in view.hops.iter_mut().zip(&snapshot.hops) {
        if let Some(info) = &hop.info {
            view_hop.asn = info.asn;
            view_hop.as_org = info.as_org.clone();
            view_hop.country = info.country_code.clone();
        }
    }
    view.mode = Some(match snapshot.mode {
        ProbeMode::Icmp => MtrModeView::Icmp,
        ProbeMode::Udp => MtrModeView::Udp,
        ProbeMode::TcpSyn { .. } => MtrModeView::Tcp,
    });
    view.port = (snapshot.port != 0).then_some(snapshot.port);
    view.reach = snapshot.reached_via.map(|via| via.label().to_owned());
    view
}

pub fn mtr_view(snapshot: &MtrSnapshot) -> MtrView {
    MtrView {
        target: snapshot.target.to_string(),
        cycle: snapshot.cycle,
        total_cycles: snapshot.total_cycles,
        hops: snapshot.hops.iter().map(hop_view).collect(),
        destination_reached: snapshot.destination_reached,
        cancelled: snapshot.cancelled,
        mode: None,
        port: None,
        reach: None,
    }
}

pub fn dns_view(lookup: &DnsLookup) -> DnsLookupView {
    DnsLookupView {
        query: lookup.query.clone(),
        requested: lookup.requested.as_str().to_owned(),
        records: lookup
            .records
            .iter()
            .map(|record| DnsRecordView {
                name: record.name.clone(),
                record_type: record.record_type().as_str().to_owned(),
                ttl: record.ttl,
                value: record.data.value(),
            })
            .collect(),
        errors: lookup
            .errors
            .iter()
            .map(|(kind, failure)| DnsErrorView {
                record_type: kind.as_str().to_owned(),
                message: failure.to_string(),
            })
            .collect(),
        elapsed_ms: u64::try_from(lookup.elapsed.as_millis()).unwrap_or(u64::MAX),
    }
}

pub fn port_view(check: &PortCheck) -> PortCheckView {
    PortCheckView {
        host: check.host.clone(),
        port: check.port,
        protocol: match check.protocol {
            PortProtocol::Tcp => "tcp",
            PortProtocol::Udp => "udp",
        }
        .to_owned(),
        state: match check.state {
            PortState::Open => PortStateView::Open,
            PortState::Closed => PortStateView::Closed,
            PortState::Filtered => PortStateView::Filtered,
            PortState::Inconclusive => PortStateView::Inconclusive,
            PortState::Error(_) => PortStateView::Error,
        },
        error: match &check.state {
            PortState::Error(message) => Some(message.clone()),
            _ => None,
        },
        remote: check.remote.map(|addr| addr.to_string()),
        elapsed_ms: u64::try_from(check.elapsed.as_millis()).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use pw_diag::fake::FakePinger;
    use pw_diag::{DiagError, EchoReply};
    use pw_netstat::ConnectionTable;
    use pw_proto::Connection;

    use super::*;

    fn ok_reply(from: &str, rtt_ms: u64) -> Result<EchoReply, DiagError> {
        Ok(EchoReply {
            status: EchoStatus::Success,
            from: Some(from.parse().unwrap()),
            rtt: Some(Duration::from_millis(rtt_ms)),
            ttl: Some(64),
        })
    }

    async fn next(rx: &mut mpsc::Receiver<serde_json::Value>) -> DiagEvent {
        let value = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("an event within 5 s")
            .expect("channel open");
        serde_json::from_value(value).unwrap()
    }

    #[tokio::test]
    async fn a_ping_job_streams_replies_then_a_summary() {
        let diag = Diag::new(Arc::new(FakePinger::new(|_, _| ok_reply("192.0.2.1", 12))));
        let mut rx = diag.subscribe();
        let started = diag
            .start_ping(PingStartRequest {
                target: "192.0.2.1".into(),
                count: Some(3),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(started.target_ip, "192.0.2.1");
        let mut replies = 0;
        loop {
            match next(&mut rx).await {
                DiagEvent::PingReply { job_id, reply } => {
                    assert_eq!(job_id, started.job_id);
                    assert_eq!(reply.outcome, EchoOutcome::Success);
                    assert!(reply.rtt_ms.unwrap() >= 12.0);
                    replies += 1;
                }
                DiagEvent::PingDone { summary, .. } => {
                    assert_eq!((summary.sent, summary.received), (3, 3));
                    assert_eq!(summary.loss_percent, 0.0);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(replies, 3);
    }

    #[tokio::test]
    async fn an_mtr_job_streams_snapshots_and_can_produce_a_report() {
        let target: IpAddr = "192.0.2.9".parse().unwrap();
        let diag = Diag::new(Arc::new(FakePinger::new(move |request, _| {
            if request.ttl >= 2 {
                ok_reply("192.0.2.9", 5)
            } else {
                Ok(EchoReply {
                    status: EchoStatus::TtlExpired,
                    from: Some("198.51.100.1".parse().unwrap()),
                    rtt: Some(Duration::from_millis(2)),
                    ttl: None,
                })
            }
        })));
        let mut rx = diag.subscribe();
        let started = diag
            .start_mtr(MtrStartRequest {
                target: target.to_string(),
                cycles: Some(2),
                resolve_names: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut last = None;
        loop {
            match next(&mut rx).await {
                DiagEvent::MtrSnapshot { snapshot, .. } => last = Some(snapshot),
                DiagEvent::MtrDone { cancelled, .. } => {
                    assert!(!cancelled);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        let last = last.expect("at least one snapshot");
        assert!(last.destination_reached);
        assert_eq!(last.hops[0].addr.as_deref(), Some("198.51.100.1"));
        assert_eq!(last.hops.last().unwrap().addr.as_deref(), Some("192.0.2.9"));

        let report = diag
            .mtr_report(started.job_id, Some("203.0.113.5".parse().unwrap()))
            .unwrap();
        assert!(report.text.contains("198.51.100.1"));
        assert!(
            report.text.contains("203.0.113.5"),
            "the source IP line is included when known"
        );
        let without = diag.mtr_report(started.job_id, None).unwrap();
        assert!(!without.text.contains("203.0.113.5"));
    }

    #[tokio::test]
    async fn a_job_can_be_cancelled() {
        let diag = Diag::new(Arc::new(
            FakePinger::new(|_, _| ok_reply("192.0.2.1", 1)).with_delay(Duration::from_millis(50)),
        ));
        let mut rx = diag.subscribe();
        let started = diag
            .start_ping(PingStartRequest {
                target: "192.0.2.1".into(),
                count: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        let _ = next(&mut rx).await; // first reply
        diag.cancel(started.job_id);
        loop {
            if let DiagEvent::PingDone { summary, .. } = next(&mut rx).await {
                assert!(summary.cancelled);
                assert!(summary.sent < 1000);
                break;
            }
        }
        diag.cancel(9999); // unknown job: not an error
    }

    #[tokio::test]
    async fn only_a_few_jobs_run_at_once() {
        let diag = Diag::new(Arc::new(
            FakePinger::new(|_, _| ok_reply("192.0.2.1", 1)).with_delay(Duration::from_millis(100)),
        ));
        for _ in 0..MAX_RUNNING_JOBS {
            diag.start_ping(PingStartRequest {
                target: "192.0.2.1".into(),
                count: Some(1000),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let refused = diag
            .start_ping(PingStartRequest {
                target: "192.0.2.1".into(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(refused.code, ErrorCode::Busy);
    }

    #[tokio::test]
    async fn bad_targets_and_requests_are_rejected_clearly() {
        let diag = Diag::new(Arc::new(FakePinger::new(|_, _| ok_reply("192.0.2.1", 1))));
        for target in ["", "   ", "bad host!", "a b"] {
            let err = diag
                .start_ping(PingStartRequest {
                    target: target.into(),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::BadRequest, "{target:?}");
        }
        assert!(diag.mtr_report(404, None).is_err());
        let err = diag
            .dns_lookup(DnsLookupRequest {
                name: "example.com".into(),
                record_type: "BOGUS".into(),
                resolver: "system".into(),
                custom_servers: vec![],
            })
            .await
            .unwrap_err();
        assert!(err.message.contains("record type"));
        let err = diag
            .dns_lookup(DnsLookupRequest {
                name: "example.com".into(),
                record_type: "A".into(),
                resolver: "custom".into(),
                custom_servers: vec!["not-an-ip".into()],
            })
            .await
            .unwrap_err();
        assert!(err.message.contains("IP addresses"));
        let err = diag
            .port_check(PortCheckRequest {
                host: "127.0.0.1".into(),
                port: 0,
                protocol: "tcp".into(),
                timeout_ms: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn a_port_check_of_a_closed_local_port_says_closed() {
        let diag = Diag::new(Arc::new(FakePinger::new(|_, _| ok_reply("192.0.2.1", 1))));
        // Bind and drop to find a port nobody listens on. Windows retries a refused loopback SYN for
        // about 2 s before reporting the reset, hence the generous timeout.
        let free = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let view = diag
            .port_check(PortCheckRequest {
                host: "127.0.0.1".into(),
                port: free,
                protocol: "tcp".into(),
                timeout_ms: Some(8000),
            })
            .await
            .unwrap();
        assert_eq!(view.state, PortStateView::Closed);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let view = diag
            .port_check(PortCheckRequest {
                host: "127.0.0.1".into(),
                port: open,
                protocol: "tcp".into(),
                timeout_ms: Some(1000),
            })
            .await
            .unwrap();
        assert_eq!(view.state, PortStateView::Open);
    }

    #[tokio::test]
    async fn local_ports_come_from_the_netstat_snapshot() {
        use crate::poller::Poller;
        use pw_netstat::fake::FakeNetStat;
        let fake = Arc::new(FakeNetStat::new());
        let row = |proto, port, state, pid| Connection {
            proto,
            local_addr: "0.0.0.0".into(),
            local_port: port,
            remote_addr: String::new(),
            remote_port: 0,
            state,
            pid,
        };
        fake.set_connections(ConnectionTable {
            rows: vec![
                row(Proto::Tcp, 3389, Some(TcpState::Listen), 1340),
                row(Proto::Tcp, 443, Some(TcpState::Established), 2204), // not a listener
                row(Proto::Udp, 53, None, 800),
                row(Proto::Tcp, 80, Some(TcpState::Listen), 2204),
            ],
            processes: [(1340, "svchost.exe".to_owned())].into(),
        });
        let snapshot = Poller::new(fake, 5, crate::trust::TrustState::new(30))
            .poll(std::time::Instant::now(), 1);
        let ports = local_ports(Some(&snapshot));
        let listed: Vec<(Proto, u16, Option<&str>)> = ports
            .ports
            .iter()
            .map(|p| (p.proto, p.port, p.process.as_deref()))
            .collect();
        assert_eq!(
            listed,
            [
                (Proto::Tcp, 80, None),
                (Proto::Tcp, 3389, Some("svchost.exe")),
                (Proto::Udp, 53, None)
            ]
        );
        assert!(local_ports(None).ports.is_empty());
    }

    /// Real ICMP/DNS/TCP through the OS. Needs internet: `cargo test -p pw-engine live_ -- --ignored --nocapture`.
    #[tokio::test]
    #[ignore = "needs internet access"]
    async fn live_ping_mtr_dns_and_port_check_against_the_real_network() {
        use pw_diag::SystemPinger;
        let diag = Diag::new(Arc::new(SystemPinger));
        let mut rx = diag.subscribe();
        let ping = diag
            .start_ping(PingStartRequest {
                target: "1.1.1.1".into(),
                count: Some(3),
                ..Default::default()
            })
            .await
            .unwrap();
        let mtr = diag
            .start_mtr(MtrStartRequest {
                target: "1.1.1.1".into(),
                cycles: Some(3),
                ..Default::default()
            })
            .await
            .unwrap();
        let (mut ping_summary, mut last_mtr, mut mtr_done) = (None, None, false);
        while ping_summary.is_none() || !mtr_done {
            match next(&mut rx).await {
                DiagEvent::PingDone { job_id, summary } if job_id == ping.job_id => {
                    ping_summary = Some(summary)
                }
                DiagEvent::MtrSnapshot { job_id, snapshot } if job_id == mtr.job_id => {
                    last_mtr = Some(snapshot)
                }
                DiagEvent::MtrDone { job_id, .. } if job_id == mtr.job_id => mtr_done = true,
                DiagEvent::Failed { message, .. } => panic!("{message}"),
                _ => {}
            }
        }
        let summary = ping_summary.unwrap();
        println!("ping: {summary:?}");
        assert!(
            summary.received > 0,
            "1.1.1.1 must answer at least one echo"
        );
        let last = last_mtr.unwrap();
        for hop in &last.hops {
            println!("hop {} {:?} loss {}%", hop.ttl, hop.addr, hop.loss_percent);
        }
        println!("{}", diag.mtr_report(mtr.job_id, None).unwrap().text);
        assert!(!last.hops.is_empty());
        let dns = diag
            .dns_lookup(DnsLookupRequest {
                name: "example.com".into(),
                record_type: "ALL".into(),
                resolver: "system".into(),
                custom_servers: vec![],
            })
            .await
            .unwrap();
        println!("dns: {} records", dns.records.len());
        assert!(dns.records.iter().any(|r| r.record_type == "A"));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = diag
            .port_check(PortCheckRequest {
                host: "127.0.0.1".into(),
                port: listener.local_addr().unwrap().port(),
                protocol: "tcp".into(),
                timeout_ms: Some(3000),
            })
            .await
            .unwrap();
        assert_eq!(open.state, PortStateView::Open);
    }

    // ---- advanced MTR (M10) ----------------------------------------------------------------------

    use pw_diag::mtr_adv::FakeProbeTransport;

    /// Answers of a path `10.0.0.1 -> 8.8.8.8 -> 1.1.1.1` (the destination), for any probe mode.
    fn path_script(request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        let rtt = Duration::from_millis(3);
        Ok(match request.ttl {
            1 => ProbeReply::ttl_expired("10.0.0.1".parse().unwrap(), rtt),
            2 => ProbeReply::ttl_expired("8.8.8.8".parse().unwrap(), rtt),
            _ => ProbeReply::reached(ReachKind::PortUnreachable, request.target, rtt),
        })
    }

    #[derive(Default)]
    struct RecordingEnricher {
        seen: Mutex<Vec<IpAddr>>,
    }

    impl HopEnricher for RecordingEnricher {
        fn lookup(&self, ip: IpAddr) -> Option<HopInfo> {
            lock(&self.seen).push(ip);
            Some(HopInfo {
                asn: Some(15169),
                as_org: Some("Example Org".to_owned()),
                country_code: Some("US".to_owned()),
            })
        }
    }

    struct Rig {
        diag: Diag<FakePinger>,
        fake: Arc<FakeProbeTransport>,
        enricher: Arc<RecordingEnricher>,
    }

    fn rig(fake: FakeProbeTransport) -> Rig {
        let fake = Arc::new(fake);
        let enricher = Arc::new(RecordingEnricher::default());
        let diag = Diag::with_parts(
            Arc::new(FakePinger::new(|request, _| {
                if request.ttl >= 3 {
                    ok_reply("1.1.1.1", 4)
                } else {
                    Ok(EchoReply {
                        status: EchoStatus::TtlExpired,
                        from: Some(
                            if request.ttl == 1 {
                                "10.0.0.1"
                            } else {
                                "8.8.8.8"
                            }
                            .parse()
                            .unwrap(),
                        ),
                        rtt: Some(Duration::from_millis(2)),
                        ttl: None,
                    })
                }
            })),
            SharedProbe::shared(Arc::clone(&fake)),
            Arc::clone(&enricher) as Arc<dyn HopEnricher>,
        );
        Rig {
            diag,
            fake,
            enricher,
        }
    }

    fn path_rig() -> Rig {
        rig(FakeProbeTransport::new(|request, _| path_script(request)))
    }

    /// Runs `request` to the end and returns the last snapshot and the job id.
    async fn run_mtr(rig: &Rig, request: MtrStartRequest) -> (u64, MtrView) {
        let mut rx = rig.diag.subscribe();
        let started = rig.diag.start_mtr(request).await.unwrap();
        let mut last = None;
        loop {
            match next(&mut rx).await {
                DiagEvent::MtrSnapshot { snapshot, .. } => last = Some(snapshot),
                DiagEvent::MtrDone { .. } => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        (started.job_id, last.expect("at least one snapshot"))
    }

    fn udp_request() -> MtrStartRequest {
        MtrStartRequest {
            target: "1.1.1.1".into(),
            cycles: Some(2),
            resolve_names: Some(false),
            mode: Some(MtrModeView::Udp),
            port: Some(5000),
            packet_size: Some(64),
            interval_ms: Some(200),
            max_hops: Some(12),
            ..Default::default()
        }
    }

    #[test]
    fn only_non_default_options_take_the_advanced_path() {
        let plain = MtrStartRequest {
            target: "x".into(),
            cycles: Some(5),
            max_hops: Some(10),
            packet_size: Some(100),
            ..Default::default()
        };
        assert!(
            !is_advanced(&plain),
            "hops and packet size work on both paths"
        );
        let with = |f: fn(&mut MtrStartRequest)| {
            let mut request = plain.clone();
            f(&mut request);
            is_advanced(&request)
        };
        assert!(!with(|r| r.mode = Some(MtrModeView::Icmp)));
        assert!(with(|r| r.mode = Some(MtrModeView::Udp)));
        assert!(with(|r| r.mode = Some(MtrModeView::Tcp)));
        assert!(with(|r| r.port = Some(80)));
        assert!(with(|r| r.interval_ms = Some(500)));
        assert!(with(|r| r.prefer_ipv6 = Some(true)));
        assert!(!with(|r| r.prefer_ipv6 = Some(false)));
    }

    #[tokio::test]
    async fn the_advanced_options_reach_the_probe_transport() {
        let rig = path_rig();
        let (_, last) = run_mtr(&rig, udp_request()).await;
        let requests = rig.fake.requests();
        assert!(!requests.is_empty());
        for request in &requests {
            assert_eq!(request.mode, ProbeMode::Udp);
            assert_eq!(request.port, 5000);
            assert_eq!(request.payload_size, 64);
            assert!(request.ttl <= 12, "the hop limit is honoured");
        }
        assert_eq!(
            rig.fake.prepared(),
            [
                (ProbeMode::Udp, "1.1.1.1".parse().unwrap()),
                (ProbeMode::Udp, "1.1.1.1".parse().unwrap())
            ],
            "prepared once at start and once by the trace"
        );
        assert_eq!(last.mode, Some(MtrModeView::Udp));
        assert_eq!(last.port, Some(5000));
        assert_eq!(last.reach.as_deref(), Some("port-unreachable"));
        assert!(last.destination_reached);

        let rig = path_rig();
        let tcp = MtrStartRequest {
            mode: Some(MtrModeView::Tcp),
            port: None,
            ..udp_request()
        };
        let (_, last) = run_mtr(&rig, tcp).await;
        let first = rig.fake.requests()[0].clone();
        assert_eq!(
            first.mode,
            ProbeMode::TcpSyn { port: 443 },
            "TCP defaults to 443"
        );
        assert_eq!(first.payload_size, 0, "a SYN carries no payload");
        assert_eq!(last.mode, Some(MtrModeView::Tcp));
        assert_eq!(last.port, Some(443));
    }

    #[tokio::test]
    async fn hops_are_enriched_with_public_addresses_only() {
        let rig = path_rig();
        let (_, last) = run_mtr(&rig, udp_request()).await;
        assert_eq!(last.hops[0].addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(last.hops[0].asn, None, "a private hop has no ASN");
        assert_eq!(last.hops[0].country, None);
        assert_eq!(last.hops[1].addr.as_deref(), Some("8.8.8.8"));
        assert_eq!(last.hops[1].asn, Some(15169));
        assert_eq!(last.hops[1].as_org.as_deref(), Some("Example Org"));
        assert_eq!(last.hops[1].country.as_deref(), Some("US"));
        let seen = lock(&rig.enricher.seen).clone();
        assert!(!seen.is_empty());
        assert!(
            seen.iter().all(|ip| is_public_ip(*ip)),
            "the enricher never saw a private address: {seen:?}"
        );
        assert!(
            seen.len() <= 2,
            "each public address is looked up once: {seen:?}"
        );
    }

    #[tokio::test]
    async fn the_default_path_stays_simple_and_is_enriched_too() {
        let rig = path_rig();
        let request = MtrStartRequest {
            target: "1.1.1.1".into(),
            cycles: Some(1),
            resolve_names: Some(false),
            ..Default::default()
        };
        let (job, last) = run_mtr(&rig, request).await;
        assert!(
            rig.fake.requests().is_empty(),
            "the probe transport is not used"
        );
        assert!(rig.fake.prepared().is_empty());
        assert_eq!(last.mode, Some(MtrModeView::Icmp));
        assert_eq!(last.port, None);
        assert_eq!(last.hops[0].asn, None);
        assert_eq!(last.hops[1].asn, Some(15169));
        let report = rig.diag.mtr_report(job, None).unwrap();
        assert!(
            !report.text.contains("Mode:"),
            "the simple report is unchanged: {}",
            report.text
        );
    }

    #[tokio::test]
    async fn the_report_of_an_advanced_job_names_mode_and_networks() {
        let rig = path_rig();
        let (job, _) = run_mtr(&rig, udp_request()).await;
        let report = rig.diag.mtr_report(job, None).unwrap();
        assert!(
            report.text.contains("Mode: UDP (port 5000)"),
            "{}",
            report.text
        );
        assert!(report.text.contains("AS15169"), "{}", report.text);
    }

    #[tokio::test]
    async fn exports_render_csv_json_and_text_with_safe_file_names() {
        let rig = path_rig();
        let (job, _) = run_mtr(&rig, udp_request()).await;
        let export = |format, source_ip: Option<&str>| {
            rig.diag.mtr_export(&MtrExportRequest {
                job_id: job,
                format,
                source_ip: source_ip.map(str::to_owned),
            })
        };
        let csv = export(MtrExportFormat::Csv, None).unwrap();
        assert_eq!(csv.format, MtrExportFormat::Csv);
        assert!(csv.content.starts_with("hop,address,"), "{}", csv.content);
        assert!(csv.content.contains("8.8.8.8"));
        assert!(csv.content.contains("15169"));
        assert!(csv.filename.starts_with("packetward-mtr-1.1.1.1-"));
        assert!(csv.filename.ends_with(".csv"));

        let json = export(MtrExportFormat::Json, Some("203.0.113.9")).unwrap();
        assert!(json.filename.ends_with(".json"));
        assert!(
            json.content.contains("\"mode\": \"udp\""),
            "{}",
            json.content
        );
        assert!(json.content.contains("203.0.113.9"));
        let parsed: serde_json::Value = serde_json::from_str(&json.content).unwrap();
        assert_eq!(parsed["port"], 5000);

        let text = export(MtrExportFormat::Text, Some("203.0.113.9")).unwrap();
        assert!(text.filename.ends_with(".txt"));
        assert!(text.content.contains("PacketWard MTR report"));
        assert!(text.content.contains("Source public IP: 203.0.113.9"));
        assert!(!export(MtrExportFormat::Text, None)
            .unwrap()
            .content
            .contains("Source public IP"));

        let bad = export(MtrExportFormat::Csv, Some("not an ip")).unwrap_err();
        assert_eq!(bad.code, ErrorCode::BadRequest);
        let unknown = rig
            .diag
            .mtr_export(&MtrExportRequest {
                job_id: 404,
                format: MtrExportFormat::Csv,
                source_ip: None,
            })
            .unwrap_err();
        assert_eq!(unknown.code, ErrorCode::BadRequest);
    }

    #[test]
    fn export_file_names_never_contain_path_or_windows_forbidden_characters() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(
            export_filename("1.1.1.1", at, "csv"),
            "packetward-mtr-1.1.1.1-20231114-221320.csv"
        );
        let hostile = export_filename("..\\..\\evil:name/x*?\"<>|", at, "txt");
        assert!(hostile.starts_with("packetward-mtr-"));
        for forbidden in ['\\', '/', ':', '*', '?', '"', '<', '>', '|'] {
            assert!(!hostile.contains(forbidden), "{hostile}");
        }
        assert!(!hostile.contains(".."), "{hostile}");
        let v6 = export_filename("2606:4700::1111", at, "json");
        assert!(!v6.contains(':'), "{v6}");
        assert!(export_filename("", at, "csv").contains("-target-"));
        assert!(export_filename(&"a".repeat(500), at, "csv").len() < 100);
    }

    #[tokio::test]
    async fn a_mode_that_cannot_run_is_refused_with_a_typed_error_before_any_job_starts() {
        // Engine::new's transport: ICMP only.
        let diag = Diag::new(Arc::new(FakePinger::new(|_, _| ok_reply("1.1.1.1", 1))));
        for mode in [MtrModeView::Udp, MtrModeView::Tcp] {
            let err = diag
                .start_mtr(MtrStartRequest {
                    target: "1.1.1.1".into(),
                    mode: Some(mode),
                    ..Default::default()
                })
                .await
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::ModeUnavailable, "{mode:?}");
            assert!(err.message.contains("capture backend"), "{}", err.message);
        }
        assert!(lock(&diag.jobs).map.is_empty(), "no job was registered");

        // A transport that refuses a mode in `prepare`, with its own reason.
        let fake = FakeProbeTransport::new(|request, _| path_script(request)).with_unavailable(
            ModeUnavailable::new(ProbeMode::TcpSyn { port: 0 }, "no Npcap here"),
        );
        let rig = rig(fake);
        let err = rig
            .diag
            .start_mtr(MtrStartRequest {
                target: "1.1.1.1".into(),
                mode: Some(MtrModeView::Tcp),
                port: Some(443),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::ModeUnavailable);
        assert!(err.message.contains("no Npcap here"), "{}", err.message);
        assert!(rig.fake.requests().is_empty(), "nothing was sent");
        // UDP still works on the same transport.
        let (_, last) = run_mtr(&rig, udp_request()).await;
        assert!(last.destination_reached);
    }

    #[tokio::test]
    async fn port_zero_is_a_bad_request() {
        let rig = path_rig();
        let err = rig
            .diag
            .start_mtr(MtrStartRequest {
                target: "1.1.1.1".into(),
                mode: Some(MtrModeView::Tcp),
                port: Some(0),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(rig.fake.requests().is_empty());
    }

    #[test]
    fn a_missing_capture_backend_is_explained_with_the_npcap_link() {
        struct NoBackend;
        impl pw_capture::CaptureEnv for NoBackend {
            fn is_windows(&self) -> bool {
                true
            }
            fn npcap_dll(&self) -> Option<std::path::PathBuf> {
                None
            }
            fn is_elevated(&self) -> bool {
                false
            }
        }
        let selection = pw_capture::select_backend(&NoBackend);
        let reason = capture_missing_reason(&selection).expect("nothing is selected");
        assert!(reason.contains("https://npcap.com"), "{reason}");
        assert!(reason.contains("administrator"), "{reason}");
        struct Elevated;
        impl pw_capture::CaptureEnv for Elevated {
            fn is_windows(&self) -> bool {
                true
            }
            fn npcap_dll(&self) -> Option<std::path::PathBuf> {
                None
            }
            fn is_elevated(&self) -> bool {
                true
            }
        }
        assert!(capture_missing_reason(&pw_capture::select_backend(&Elevated)).is_none());
    }

    #[tokio::test]
    async fn hostnames_resolve_and_ip_literals_pass_through() {
        assert_eq!(
            resolve_target("127.0.0.1").await.unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolve_target("::ffff:192.0.2.5").await.unwrap(),
            "192.0.2.5".parse::<IpAddr>().unwrap()
        );
        let localhost = resolve_target("localhost").await.unwrap();
        assert!(localhost.is_loopback());
    }
}
