// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-engine — orchestrator: wires every crate together, owns tasks and state, exposes the API.
//!
//! Answers `system.info` and `netstat.connections`, and publishes the `live.heartbeat` and
//! `live.stats` topics. The engine implements [`pw_ipc::Handler`] itself, so the agent only has to
//! hand it to `pw_ipc::serve`.

mod capture;
mod connections;
mod defense;
mod detect;
mod diag;
mod intel;
mod poller;
mod rdp_shield;
mod speed;
mod support;
mod sys;
mod trust;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use pw_diag::SystemPinger;
use pw_ipc::{EventReceiver, Handler};
use pw_netstat::NetStat;
use pw_proto::{
    method, topic, AbuseCheckRequest, AbuseKeyRequest, AllowlistConfig, BlockRequest,
    CaptureFileRequest, CaptureStartRequest, ConnectionsRequest, DiagJobRequest as SpeedJobRequest,
    DiagJobRequest, DnsLookupRequest, ErrorCode, ErrorPayload, FirewallRuleAction,
    FirewallRuleEdit, FirewallRulesRequest, GeoLookupRequest, Heartbeat, HelloResponse,
    ListEnableRequest, ListRefreshRequest, MtrStartRequest, PingStartRequest, PortCheckRequest,
    PurgeRequest, RdpAttempts, RdpConfirmRequest, RdpEndSessionRequest, RdpLockoutRequest,
    RdpNlaRequest, RdpPortRequest, RdpRestrictRequest, RecordStartRequest, SetGuardianPolicy,
    SpeedRequest, SupportBundleRequest, SupportDiscardRequest, SupportReadRequest, SystemInfo,
    UnblockRequest, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

pub use capture::ensure_private_dir;
pub use capture::{CaptureHost, CaptureManager, PacketSink, SystemCaptureHost};
pub use defense::{Defense, JsonPersistence, MemoryPersistence, Persistence};
pub use detect::{AlertStore, DetectionService, KEEP_INCIDENTS};
pub use diag::{Diag, MAX_RUNNING_JOBS};
pub use intel::{IntelApi, IntelService, OfflineFetcher};
pub use poller::{Poller, Snapshot};
pub use rdp_shield::RdpShield;
pub use speed::{SpeedApi, SpeedService, UnavailableSpeed};
pub use trust::{TrustState, DEFAULT_WINDOW_DAYS};

/// Events buffered per subscription before the producer waits for the consumer.
const SUBSCRIPTION_QUEUE: usize = 4;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub agent_version: String,
    /// True under the service control manager, false for `run --console`.
    pub service_mode: bool,
    pub heartbeat_interval: Duration,
    /// How often the network state is read and `live.stats` published.
    pub poll_interval: Duration,
    /// The RDP sessions are refreshed every this many polls.
    pub rdp_refresh_every: u32,
    /// How many days back a successful RDP logon keeps an address trusted (1..=365). Will be set
    /// from `config.toml` once the config model exists.
    pub rdp_trust_days: u32,
    /// Where recordings are written (administrators only). Created on first use.
    pub capture_dir: PathBuf,
    /// Where finished support bundles wait to be collected (administrators only).
    pub support_dir: PathBuf,
    /// The agent log folder, read for the support bundle.
    pub logs_dir: PathBuf,
    /// Alerts are appended here as JSON lines so the inbox survives restarts. `None` (the default of
    /// `EngineConfig::new`) keeps them in memory only; the agent sets the real path.
    pub alerts_log: Option<PathBuf>,
    /// Where the blocks, the Guardian policy, the allowlist and the audit log are kept (`None`: in
    /// memory only, as in tests).
    pub defense_dir: Option<PathBuf>,
    /// GeoIP databases, cached blocklists and their settings (`None`: nothing is kept).
    pub intel_dir: Option<PathBuf>,
    /// How sensitive the detectors are.
    pub detect_preset: pw_detect::Preset,
    /// How often the detectors are ticked.
    pub detect_interval: Duration,
    /// Start the live capture when the engine starts. Off by default so tests and tools that build
    /// an engine never open a capture; the agent turns it on.
    pub capture_autostart: bool,
}

impl EngineConfig {
    pub fn new(agent_version: impl Into<String>, service_mode: bool) -> Self {
        Self {
            agent_version: agent_version.into(),
            service_mode,
            heartbeat_interval: Duration::from_secs(1),
            poll_interval: Duration::from_secs(1),
            rdp_refresh_every: 5,
            rdp_trust_days: DEFAULT_WINDOW_DAYS,
            capture_dir: data_dir().join("captures"),
            support_dir: data_dir().join("support"),
            logs_dir: data_dir().join("logs"),
            alerts_log: None,
            defense_dir: None,
            intel_dir: None,
            detect_preset: pw_detect::Preset::Balanced,
            detect_interval: Duration::from_secs(1),
            capture_autostart: false,
        }
    }
}

/// Aborts the polling task when the engine goes away.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct Engine {
    config: EngineConfig,
    started: Instant,
    latest: watch::Receiver<Option<Arc<Snapshot>>>,
    diag: Diag<SystemPinger>,
    capture: Arc<CaptureManager>,
    support: support::SupportService,
    alerts: Arc<AlertStore>,
    defense: Arc<Defense>,
    detection: Arc<DetectionService>,
    shield: Arc<RdpShield>,
    speed: Arc<dyn SpeedApi>,
    intel: Arc<dyn IntelApi>,
    _poller: AbortOnDrop,
    _detector: AbortOnDrop,
    _guardian: AbortOnDrop,
    _upkeep: AbortOnDrop,
    _shield: AbortOnDrop,
    _intel: AbortOnDrop,
}

impl Engine {
    /// Starts the engine and its network poller. Must be called inside a tokio runtime.
    pub fn new(config: EngineConfig, netstat: Arc<dyn NetStat>) -> Self {
        Self::with_capture_host(config, netstat, Arc::new(SystemCaptureHost), None)
    }

    /// [`Engine::new`] with the real Windows Firewall. Only the agent calls this: `new` and the
    /// tests use an in-memory firewall, so nothing but the agent can change the machine's rules.
    #[cfg(windows)]
    pub fn with_system_firewall(config: EngineConfig, netstat: Arc<dyn NetStat>) -> Self {
        Self::build(
            config,
            netstat,
            Arc::new(SystemCaptureHost),
            None,
            Arc::new(pw_firewall::system_firewall()),
            Arc::new(pw_netstat::WindowsRdpControl),
            system_speed(),
            system_intel_parts(),
        )
    }

    /// `Engine::new` with another capture host (tests) and an optional consumer of every captured
    /// batch (the detection engine).
    pub fn with_capture_host(
        config: EngineConfig,
        netstat: Arc<dyn NetStat>,
        host: Arc<dyn CaptureHost>,
        sink: Option<PacketSink>,
    ) -> Self {
        let firewall: Arc<dyn pw_firewall::Firewall> = Arc::new(pw_firewall::FirewallManager::new(
            pw_firewall::fake::FakeFirewall::windows_defaults(),
        ));
        let control: Arc<dyn pw_netstat::rdp_control::RdpControl> =
            Arc::new(pw_netstat::rdp_control::FakeRdpControl::new());
        Self::build(
            config,
            netstat,
            host,
            sink,
            firewall,
            control,
            Arc::new(UnavailableSpeed),
            IntelParts::Offline,
        )
    }

    #[allow(clippy::too_many_arguments)] // private constructor: one argument per injectable backend
    fn build(
        config: EngineConfig,
        netstat: Arc<dyn NetStat>,
        host: Arc<dyn CaptureHost>,
        sink: Option<PacketSink>,
        firewall: Arc<dyn pw_firewall::Firewall>,
        control: Arc<dyn pw_netstat::rdp_control::RdpControl>,
        speed: Arc<dyn SpeedApi>,
        intel_parts: IntelParts,
    ) -> Self {
        let (publish, latest) = watch::channel(None);
        let trust = TrustState::new(config.rdp_trust_days);
        let alerts = Arc::new(AlertStore::new(config.alerts_log.clone()));
        // Learning RDP logons reads the event log (a bounded initial load, then live events); it
        // blocks, so it runs on a blocking thread and never delays the first snapshot.
        {
            let netstat = Arc::clone(&netstat);
            let trust = Arc::clone(&trust);
            let alerts = Arc::clone(&alerts);
            tokio::task::spawn_blocking(move || {
                // A successful logon from an address never seen before is worth a notification; the
                // initial load of history (feed still "loading") never is.
                let recorder = trust.sink();
                let watcher = Arc::clone(&trust);
                let alerts = Arc::clone(&alerts);
                let counter = std::sync::atomic::AtomicU64::new(1);
                let sink: pw_netstat::LogonSink = Arc::new(move |event| {
                    let known = watcher
                        .addresses(poller::unix_ms())
                        .iter()
                        .any(|a| a.addr == event.addr.to_string());
                    let ready = watcher.feed() == pw_proto::TrustFeed::Ready;
                    recorder(event);
                    if ready && !known {
                        let id = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let known_count = watcher.addresses(poller::unix_ms()).len();
                        let started = detect::new_logon_alert(
                            id,
                            &event.addr.to_string(),
                            event.at_unix_ms,
                            known_count,
                        );
                        let mut ended = started.clone();
                        ended.phase = pw_proto::AlertPhaseView::Ended;
                        alerts.record(started);
                        alerts.record(ended);
                    }
                });
                let state = netstat.start_logon_feed(trust.window_ms(), sink);
                trust.set_feed(state);
            });
        }
        // Detection: fed by netstat, the adapter counters, the failed-logon feed and (when it works)
        // the packet capture. The alerts it raises are kept, persisted and pushed to subscribers.
        let detection = Arc::new(DetectionService::new(
            config.detect_preset,
            Arc::clone(&alerts),
        ));
        {
            let netstat = Arc::clone(&netstat);
            let detection = Arc::clone(&detection);
            tokio::task::spawn_blocking(move || {
                let feed: pw_netstat::LogonSink =
                    Arc::new(move |event| detection.logon_failure(event));
                if !netstat.start_failure_feed(feed) {
                    tracing::warn!(
                        "failed logons cannot be read: RDP brute force will not be detected"
                    );
                }
            });
        }
        let detector_task = tokio::spawn(detect_loop(
            Arc::clone(&detection),
            latest.clone(),
            Arc::clone(&trust),
            config.detect_interval,
        ));
        let packet_sink: PacketSink = {
            let detection = Arc::clone(&detection);
            Arc::new(move |batch| {
                detection.ingest(batch);
                if let Some(extra) = &sink {
                    extra(batch);
                }
            })
        };
        // Firewall manager and Guardian: the protected set is the machine's own gateway and DNS
        // servers, the addresses with a successful RDP logon and the user's allowlist.
        let context = Arc::new(RwLock::new(pw_netstat::NetworkContext::default()));
        let persistence: Arc<dyn Persistence> = match &config.defense_dir {
            Some(dir) => Arc::new(JsonPersistence::new(dir.clone())),
            None => Arc::new(MemoryPersistence::default()),
        };
        let defense_firewall = Arc::clone(&firewall);
        let defense = Arc::new(Defense::new(
            firewall,
            persistence,
            Arc::clone(&context),
            Arc::clone(&trust),
        ));
        detection.set_preset(preset_of(defense.policy().preset));
        let intel: Arc<dyn IntelApi> = match intel_parts {
            IntelParts::Offline => Arc::new(IntelService::new(
                OfflineFetcher,
                Arc::new(pw_intel::MemorySecretStore::new()),
                config.intel_dir.clone(),
                Arc::clone(&defense),
            )),
            #[cfg(feature = "net-http")]
            IntelParts::Http(fetcher, secrets) => Arc::new(IntelService::new(
                fetcher,
                secrets,
                config.intel_dir.clone(),
                Arc::clone(&defense),
            )),
        };
        let intel_task = tokio::spawn(intel_loop(Arc::clone(&intel)));
        let shield = Arc::new(RdpShield::new(
            control,
            Arc::clone(&defense_firewall),
            Arc::clone(&trust),
            Arc::clone(&defense),
            config.defense_dir.clone(),
        ));
        if let Some(attempts) = shield.saved_attempts() {
            detection.set_rdp_attempts(attempts.threshold, attempts.window_secs);
        }
        let shield_task = tokio::spawn(shield_loop(Arc::clone(&shield)));
        let guardian_task = tokio::spawn(guardian_loop(Arc::clone(&defense), alerts.events()));
        let upkeep_task = tokio::spawn(upkeep_loop(
            Arc::clone(&defense),
            Arc::clone(&netstat),
            context,
        ));
        let task = tokio::spawn(poll_loop(
            netstat,
            publish,
            config.poll_interval,
            config.rdp_refresh_every,
            trust,
        ));
        let capture = Arc::new(CaptureManager::new(
            host,
            config.capture_dir.clone(),
            Some(packet_sink),
        ));
        if config.capture_autostart {
            let capture = Arc::clone(&capture);
            tokio::spawn(async move {
                let cleaner = Arc::clone(&capture);
                if let Ok(removed) = tokio::task::spawn_blocking(move || cleaner.cleanup()).await {
                    if removed > 0 {
                        tracing::info!(removed, "deleted old recordings");
                    }
                }
                match capture.start(None).await {
                    Ok(()) => tracing::info!("live capture started"),
                    Err(err) => tracing::warn!(reason = %err.message, "live capture did not start"),
                }
            });
        }
        let support =
            support::SupportService::new(config.support_dir.clone(), config.logs_dir.clone());
        Self {
            config,
            started: Instant::now(),
            latest,
            diag: Diag::new(Arc::new(SystemPinger)),
            support,
            capture,
            alerts,
            defense,
            detection,
            shield,
            speed,
            intel,
            _poller: AbortOnDrop(task),
            _detector: AbortOnDrop(detector_task),
            _guardian: AbortOnDrop(guardian_task),
            _upkeep: AbortOnDrop(upkeep_task),
            _shield: AbortOnDrop(shield_task),
            _intel: AbortOnDrop(intel_task),
        }
    }

    fn shield_inputs(&self) -> rdp_shield::Inputs {
        let latest = self.latest.borrow().clone();
        rdp_shield::Inputs {
            listening_ports: latest
                .as_ref()
                .map(|snapshot| {
                    snapshot
                        .table
                        .rows
                        .iter()
                        .filter(|r| {
                            r.proto == pw_proto::Proto::Tcp
                                && r.state == Some(pw_proto::TcpState::Listen)
                        })
                        .map(|r| r.local_port)
                        .collect()
                })
                .unwrap_or_default(),
            logon_audit: latest
                .as_ref()
                .map(|snapshot| snapshot.stats.rdp_trust.audit)
                .unwrap_or_default(),
        }
    }

    async fn rdp_audit(&self) -> Result<Value, ErrorPayload> {
        let shield = Arc::clone(&self.shield);
        let inputs = self.shield_inputs();
        blocking(move || shield.audit(&inputs))
            .await
            .and_then(|v| to_value(&v))
    }

    fn support_inputs(&self) -> support::Inputs {
        support::Inputs {
            info: self.system_info(),
            stats: self
                .latest
                .borrow()
                .as_ref()
                .map(|snapshot| snapshot.stats.clone()),
            capture: self.capture.status(),
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn system_info(&self) -> SystemInfo {
        SystemInfo {
            agent_version: self.config.agent_version.clone(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            hostname: hostname(),
            os_family: std::env::consts::OS.to_owned(),
            pid: std::process::id(),
            uptime_secs: self.uptime_secs(),
            service_mode: self.config.service_mode,
        }
    }
}

/// What the engine is given to build the intel service with.
pub(crate) enum IntelParts {
    /// No network: the local database and cached lists work, nothing is downloaded.
    Offline,
    #[cfg(feature = "net-http")]
    Http(pw_intel::HttpFetcher, Arc<dyn pw_intel::SecretStore>),
}

/// Refreshes the blocklists that are due, shortly after start and then every ten minutes.
async fn intel_loop(intel: Arc<dyn IntelApi>) {
    tokio::time::sleep(Duration::from_secs(30)).await;
    let mut ticker = tokio::time::interval(Duration::from_secs(600));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(err) = intel.tick().await {
            tracing::warn!(reason = %err.message, "the blocklist refresh failed");
        }
    }
}

/// Reverts RDP changes nobody confirmed in time. The very first pass runs at once: a change that
/// outlived an agent restart was never confirmed.
async fn shield_loop(shield: Arc<RdpShield>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let shield = Arc::clone(&shield);
        if let Err(err) = tokio::task::spawn_blocking(move || shield.tick()).await {
            tracing::error!(%err, "the RDP Shield check failed");
        }
    }
}

/// Turns alerts into blocks (or Monitor-mode decisions). The firewall calls block, so they run on a
/// blocking thread.
async fn guardian_loop(
    defense: Arc<Defense>,
    mut events: tokio::sync::broadcast::Receiver<pw_proto::AlertView>,
) {
    loop {
        match events.recv().await {
            Ok(alert) => {
                let defense = Arc::clone(&defense);
                if let Err(err) =
                    tokio::task::spawn_blocking(move || defense.on_alert(&alert)).await
                {
                    tracing::error!(%err, "the Guardian failed on an alert");
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Keeps the machine's gateway and DNS servers current and expires/re-applies blocks. The firewall is
/// only touched when there is something desired or something of ours already there.
async fn upkeep_loop(
    defense: Arc<Defense>,
    netstat: Arc<dyn NetStat>,
    context: Arc<RwLock<pw_netstat::NetworkContext>>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(10));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut round = 0u32;
    loop {
        ticker.tick().await;
        let defense = Arc::clone(&defense);
        let netstat = Arc::clone(&netstat);
        let context = Arc::clone(&context);
        let refresh_context = round.is_multiple_of(3);
        round = round.wrapping_add(1);
        let job = tokio::task::spawn_blocking(move || {
            if refresh_context {
                let fresh = netstat.network_context();
                *context
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
            }
            if let Err(err) = defense.reconcile() {
                tracing::warn!(reason = %err.message, "could not apply the blocks to the firewall");
            }
        });
        if let Err(err) = job.await {
            tracing::error!(%err, "the firewall upkeep failed");
        }
    }
}

/// Ticks the detectors every `period` with the latest network snapshot, and keeps the set of
/// protected sources (addresses with a successful RDP logon) current.
async fn detect_loop(
    detection: Arc<DetectionService>,
    latest: watch::Receiver<Option<Arc<Snapshot>>>,
    trust: Arc<TrustState>,
    period: Duration,
) {
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let snapshot = latest.borrow().clone();
        let trusted: Vec<String> = trust
            .addresses(poller::unix_ms())
            .into_iter()
            .map(|a| a.addr)
            .collect();
        let detection = Arc::clone(&detection);
        let job = tokio::task::spawn_blocking(move || {
            detection.set_protected(detect::protected_from(&trusted));
            detect::tick_now(&detection, snapshot.as_deref())
        });
        if let Err(err) = job.await {
            tracing::error!(%err, "the detection tick failed");
        }
    }
}

/// Reads the network on a blocking thread every `period` and publishes the result.
async fn poll_loop(
    netstat: Arc<dyn NetStat>,
    publish: watch::Sender<Option<Arc<Snapshot>>>,
    period: Duration,
    rdp_every: u32,
    trust: Arc<TrustState>,
) {
    let mut poller = Some(Poller::new(
        Arc::clone(&netstat),
        rdp_every,
        Arc::clone(&trust),
    ));
    let mut ticker = tokio::time::interval(period);
    // A slow poll delays the next one instead of queueing a burst of catch-up polls.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        // If a previous poll panicked the poller was lost with it; start over with a fresh one.
        let mut current = poller
            .take()
            .unwrap_or_else(|| Poller::new(Arc::clone(&netstat), rdp_every, Arc::clone(&trust)));
        let job = tokio::task::spawn_blocking(move || {
            let snapshot = current.poll(std::time::Instant::now(), poller::unix_ms());
            (current, snapshot)
        });
        match job.await {
            Ok((returned, snapshot)) => {
                poller = Some(returned);
                publish.send_replace(Some(Arc::new(snapshot)));
            }
            Err(err) => tracing::error!(%err, "the network poll failed; restarting the poller"),
        }
    }
}

fn hostname() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned())
}

impl Handler for Engine {
    fn hello(&self) -> HelloResponse {
        HelloResponse {
            agent_version: self.config.agent_version.clone(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        }
    }

    async fn handle(&self, method_name: &str, payload: Value) -> Result<Value, ErrorPayload> {
        match method_name {
            method::SYSTEM_INFO => to_value(&self.system_info()),
            method::NETSTAT_CONNECTIONS => {
                let request: ConnectionsRequest = if payload.is_null() {
                    ConnectionsRequest::default()
                } else {
                    serde_json::from_value(payload)
                        .map_err(|err| ErrorPayload::new(ErrorCode::BadRequest, err.to_string()))?
                };
                let latest = self.latest.borrow().clone();
                to_value(&connections::response(latest.as_deref(), request.limit))
            }
            method::DIAG_PING_START => {
                let request: PingStartRequest = parse(payload)?;
                to_value(&self.diag.start_ping(request).await?)
            }
            method::DIAG_MTR_START => {
                let request: MtrStartRequest = parse(payload)?;
                to_value(&self.diag.start_mtr(request).await?)
            }
            method::DIAG_CANCEL => {
                let request: DiagJobRequest = parse(payload)?;
                self.diag.cancel(request.job_id);
                Ok(Value::Null)
            }
            method::DIAG_MTR_REPORT => {
                let request: DiagJobRequest = parse(payload)?;
                // The public IP of this machine is learned from a XeroHost node (M9); until then the
                // report simply omits that line.
                to_value(&self.diag.mtr_report(request.job_id, None)?)
            }
            method::DIAG_DNS_LOOKUP => {
                let request: DnsLookupRequest = parse(payload)?;
                to_value(&self.diag.dns_lookup(request).await?)
            }
            method::DIAG_PORT_CHECK => {
                let request: PortCheckRequest = parse(payload)?;
                to_value(&self.diag.port_check(request).await?)
            }
            method::DIAG_PORTS_LOCAL => {
                let latest = self.latest.borrow().clone();
                to_value(&diag::local_ports(latest.as_deref()))
            }
            method::CAPTURE_STATUS => to_value(&self.capture.status()),
            method::CAPTURE_START => {
                let request: CaptureStartRequest = parse_or_default(payload)?;
                self.capture.start(request.interface.as_deref()).await?;
                to_value(&self.capture.status())
            }
            method::CAPTURE_STOP => {
                self.capture.stop().await;
                to_value(&self.capture.status())
            }
            method::CAPTURE_RECORD_START => {
                let request: RecordStartRequest = parse(payload)?;
                self.capture.record_start(request).await?;
                to_value(&self.capture.status())
            }
            method::CAPTURE_RECORD_STOP => {
                self.capture.record_stop().await?;
                to_value(&self.capture.status())
            }
            method::CAPTURE_FILES => to_value(&self.capture.files()),
            method::CAPTURE_FILES_DELETE => {
                let request: CaptureFileRequest = parse(payload)?;
                self.capture.delete_file(&request.name)?;
                to_value(&self.capture.files())
            }
            method::SUPPORT_PREVIEW => {
                let request: SupportBundleRequest = parse(payload)?;
                to_value(&self.support.preview(&self.support_inputs(), &request))
            }
            method::SUPPORT_CREATE => {
                let request: SupportBundleRequest = parse(payload)?;
                let info = self
                    .support
                    .create(self.support_inputs(), request, &self.capture)
                    .await?;
                to_value(&info)
            }
            method::SUPPORT_READ => {
                let request: SupportReadRequest = parse(payload)?;
                to_value(&self.support.read(&request)?)
            }
            method::SUPPORT_DISCARD => {
                let request: SupportDiscardRequest = parse(payload)?;
                self.support.discard(&request.id);
                Ok(Value::Null)
            }
            method::RDP_AUDIT => {
                let shield = Arc::clone(&self.shield);
                let inputs = self.shield_inputs();
                blocking(move || shield.audit(&inputs))
                    .await
                    .and_then(|v| to_value(&v))
            }
            method::RDP_RESTRICT => {
                let request: RdpRestrictRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.restrict(&request)).await?;
                self.rdp_audit().await
            }
            method::RDP_UNRESTRICT => {
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.unrestrict()).await?;
                self.rdp_audit().await
            }
            method::RDP_PORT => {
                let request: RdpPortRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                let inputs = self.shield_inputs();
                blocking(move || shield.change_port(&request, &inputs)).await?;
                self.rdp_audit().await
            }
            method::RDP_NLA => {
                let request: RdpNlaRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.set_nla(request.required)).await?;
                self.rdp_audit().await
            }
            method::RDP_LOCKOUT => {
                let request: RdpLockoutRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.set_lockout(&request)).await?;
                self.rdp_audit().await
            }
            method::RDP_ATTEMPTS => {
                let attempts: RdpAttempts = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                let saved = blocking(move || shield.set_attempts(attempts)).await?;
                self.detection
                    .set_rdp_attempts(saved.threshold, saved.window_secs);
                self.rdp_audit().await
            }
            method::RDP_CONFIRM => {
                let request: RdpConfirmRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.confirm(request.id)).await?;
                self.rdp_audit().await
            }
            method::RDP_CANCEL => {
                let request: RdpConfirmRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.cancel(request.id)).await?;
                self.rdp_audit().await
            }
            method::RDP_RESET => {
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.reset()).await?;
                self.rdp_audit().await
            }
            method::RDP_END_SESSION => {
                let request: RdpEndSessionRequest = parse(payload)?;
                let shield = Arc::clone(&self.shield);
                blocking(move || shield.end_session(&request)).await?;
                Ok(Value::Null)
            }
            method::INTEL_GEO_STATUS => to_value(&self.intel.geo_status()),
            method::INTEL_GEO_UPDATE => to_value(&self.intel.geo_update()?),
            method::INTEL_LOOKUP => {
                let request: GeoLookupRequest = parse(payload)?;
                to_value(&self.intel.lookup(&request)?)
            }
            method::INTEL_LISTS => to_value(&self.intel.lists()),
            method::INTEL_LIST_ENABLE => {
                let request: ListEnableRequest = parse(payload)?;
                to_value(&self.intel.set_list_enabled(request).await?)
            }
            method::INTEL_LIST_REFRESH => {
                let request: ListRefreshRequest = parse(payload)?;
                to_value(&self.intel.refresh_list(request).await?)
            }
            method::INTEL_ABUSE_STATUS => to_value(&self.intel.abuse_status()),
            method::INTEL_ABUSE_SET_KEY => {
                let request: AbuseKeyRequest = parse(payload)?;
                to_value(&self.intel.set_abuse_key(request)?)
            }
            method::INTEL_ABUSE_CHECK => {
                let request: AbuseCheckRequest = parse(payload)?;
                to_value(&self.intel.abuse_check(request).await?)
            }
            method::SPEED_START => {
                let request: SpeedRequest = parse(payload)?;
                to_value(&self.speed.start(request)?)
            }
            method::SPEED_CANCEL => {
                let request: SpeedJobRequest = parse(payload)?;
                self.speed.cancel(request.job_id);
                Ok(Value::Null)
            }
            method::ALERTS_LIST => to_value(&self.alerts.list()),
            method::ALERTS_CLEAR => {
                self.alerts.clear_ended();
                to_value(&self.alerts.list())
            }
            method::FIREWALL_RULES => {
                let request: FirewallRulesRequest = parse_or_default(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.rules(&request))
                    .await
                    .and_then(|v| to_value(&v))
            }
            method::FIREWALL_RULE_ADD => {
                let edit: FirewallRuleEdit = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.add_rule(&edit, "ui")).await?;
                Ok(Value::Null)
            }
            method::FIREWALL_RULE_UPDATE => {
                let edit: FirewallRuleEdit = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.update_rule(&edit, "ui")).await?;
                Ok(Value::Null)
            }
            method::FIREWALL_RULE_REMOVE => {
                let action: FirewallRuleAction = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.remove_rule(&action, "ui")).await?;
                Ok(Value::Null)
            }
            method::FIREWALL_RULE_ENABLE => {
                let action: FirewallRuleAction = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.enable_rule(&action, "ui")).await?;
                Ok(Value::Null)
            }
            method::FIREWALL_BLOCKS => to_value(&self.defense.list_blocks()),
            method::FIREWALL_BLOCK => {
                let request: BlockRequest = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.block(&request, "ui"))
                    .await
                    .and_then(|v| to_value(&v))
            }
            method::FIREWALL_UNBLOCK => {
                let request: UnblockRequest = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.unblock(&request.targets, "ui"))
                    .await
                    .and_then(|v| to_value(&v))
            }
            method::FIREWALL_UNBLOCK_ALL => {
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.unblock_all("ui"))
                    .await
                    .and_then(|v| to_value(&v))
            }
            method::FIREWALL_PURGE => {
                let request: PurgeRequest = parse_or_default(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.purge(&request, "ui"))
                    .await
                    .and_then(|v| to_value(&v))
            }
            method::GUARDIAN_STATUS => to_value(&self.defense.status()),
            method::GUARDIAN_SET_POLICY => {
                let request: SetGuardianPolicy = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                let status = blocking(move || defense.set_policy(&request, "ui")).await?;
                self.detection.set_preset(preset_of(status.policy.preset));
                to_value(&status)
            }
            method::GUARDIAN_ALLOWLIST => to_value(&self.defense.allowlist()),
            method::GUARDIAN_SET_ALLOWLIST => {
                let config: AllowlistConfig = parse(payload)?;
                let defense = Arc::clone(&self.defense);
                blocking(move || defense.set_allowlist(config, "ui"))
                    .await
                    .and_then(|v| to_value(&v))
            }
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownMethod,
                format!("unknown method `{other}`"),
            )),
        }
    }

    async fn subscribe(&self, topic_name: &str) -> Result<EventReceiver, ErrorPayload> {
        match topic_name {
            topic::LIVE_HEARTBEAT => {
                let (tx, rx) = mpsc::channel(SUBSCRIPTION_QUEUE);
                let started = self.started;
                let period = self.config.heartbeat_interval;
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(period);
                    let mut seq = 0u64;
                    loop {
                        ticker.tick().await;
                        seq += 1;
                        let beat = Heartbeat {
                            seq,
                            uptime_secs: started.elapsed().as_secs(),
                            unix_ms: poller::unix_ms(),
                        };
                        let Ok(payload) = serde_json::to_value(beat) else {
                            continue;
                        };
                        // The consumer going away (unsubscribe, disconnect) ends the producer.
                        if tx.send(payload).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(rx)
            }
            topic::LIVE_STATS => {
                let (tx, rx) = mpsc::channel(SUBSCRIPTION_QUEUE);
                let mut latest = self.latest.clone();
                tokio::spawn(async move {
                    loop {
                        // The current value first (a late subscriber must not wait a second), then
                        // every change. `watch` coalesces: a slow consumer skips to the newest.
                        let payload = latest
                            .borrow_and_update()
                            .as_ref()
                            .map(|snapshot| serde_json::to_value(&snapshot.stats));
                        if let Some(Ok(payload)) = payload {
                            if tx.send(payload).await.is_err() {
                                break;
                            }
                        }
                        if latest.changed().await.is_err() {
                            break;
                        }
                    }
                });
                Ok(rx)
            }
            topic::DIAG_PROGRESS => Ok(self.diag.subscribe()),
            topic::ALERTS => Ok(self.alerts.subscribe()),
            topic::SPEED_PROGRESS => Ok(self.speed.subscribe()),
            topic::CAPTURE_STATS => {
                let (tx, rx) = mpsc::channel(SUBSCRIPTION_QUEUE);
                let mut live = self.capture.subscribe();
                tokio::spawn(async move {
                    loop {
                        match live.recv().await {
                            Ok(stats) => {
                                let Ok(payload) = serde_json::to_value(&stats) else {
                                    continue;
                                };
                                if tx.send(payload).await.is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
                Ok(rx)
            }
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownTopic,
                format!("unknown topic `{other}`"),
            )),
        }
    }
}

/// Like `parse`, but a missing payload means "all defaults".
fn parse_or_default<T: serde::de::DeserializeOwned + Default>(
    payload: Value,
) -> Result<T, ErrorPayload> {
    if payload.is_null() {
        Ok(T::default())
    } else {
        parse(payload)
    }
}

/// The agent data folder under `%ProgramData%`, falling back to the Windows default location.
fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:ProgramData"), PathBuf::from)
        .join("PacketWard")
}

#[cfg(windows)]
fn system_intel_parts() -> IntelParts {
    #[cfg(feature = "net-http")]
    {
        match pw_intel::HttpFetcher::new(&pw_intel::HttpFetcherConfig::default()) {
            Ok(fetcher) => {
                return IntelParts::Http(fetcher, Arc::new(pw_intel::secret::KeyringSecretStore))
            }
            Err(err) => {
                tracing::warn!(%err, "no network transport for the threat intelligence downloads")
            }
        }
    }
    IntelParts::Offline
}

/// The speed test of the real agent: HTTP(S) with the system proxy (needs the `speed-http` feature).
#[cfg(windows)]
fn system_speed() -> Arc<dyn SpeedApi> {
    #[cfg(feature = "net-http")]
    {
        use pw_diag::speed::{HttpTransport, HttpTransportConfig};
        match HttpTransport::new(&HttpTransportConfig::default()) {
            // XeroHost nodes: the list is published in the blocklist repository (nodes.json); until a node
            // list is loaded only the user's own servers are used.
            Ok(transport) => return Arc::new(SpeedService::new(transport, Vec::new())),
            Err(err) => tracing::warn!(%err, "the speed test has no network transport"),
        }
    }
    Arc::new(UnavailableSpeed)
}

fn preset_of(preset: pw_proto::GuardianPreset) -> pw_detect::Preset {
    match preset {
        pw_proto::GuardianPreset::Gentle => pw_detect::Preset::Gentle,
        pw_proto::GuardianPreset::Balanced => pw_detect::Preset::Balanced,
        pw_proto::GuardianPreset::Strict => pw_detect::Preset::Strict,
    }
}

/// Runs a call that blocks (firewall COM, disk) off the async workers.
async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, ErrorPayload> + Send + 'static,
) -> Result<T, ErrorPayload> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string()))?
}

fn parse<T: serde::de::DeserializeOwned>(payload: Value) -> Result<T, ErrorPayload> {
    serde_json::from_value(payload)
        .map_err(|err| ErrorPayload::new(ErrorCode::BadRequest, err.to_string()))
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, ErrorPayload> {
    serde_json::to_value(value)
        .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pw_ipc::memory::{memory_pair, MemoryConnector};
    use pw_ipc::{serve, Client, ClientError};
    use pw_netstat::fake::FakeNetStat;
    use pw_netstat::ConnectionTable;
    use pw_proto::{
        ClientKind, Connection, ConnectionsResponse, LiveStats, Proto, TcpState, MAX_FRAME_BYTES,
    };

    use super::*;

    // The connector must outlive the test: when all connectors are gone the in-memory listener
    // reports an accept error and `serve` stops, taking its connections with it.
    async fn connect_with(
        config: EngineConfig,
        netstat: Arc<FakeNetStat>,
    ) -> (Client, MemoryConnector) {
        let (listener, connector) = memory_pair();
        let engine = Arc::new(Engine::new(config, netstat));
        tokio::spawn(serve(listener, engine, std::future::pending()));
        let stream = connector.connect().await.unwrap();
        let client = Client::connect(stream, ClientKind::Pwctl, "test")
            .await
            .unwrap();
        (client, connector)
    }

    async fn connect(config: EngineConfig) -> (Client, MemoryConnector) {
        connect_with(config, Arc::new(FakeNetStat::new())).await
    }

    fn fast(mut config: EngineConfig) -> EngineConfig {
        config.poll_interval = Duration::from_millis(20);
        config
    }

    fn row(remote: &str, i: u32) -> Connection {
        Connection {
            proto: Proto::Tcp,
            local_addr: "10.0.0.5".into(),
            local_port: 443,
            remote_addr: remote.into(),
            remote_port: 40000 + (i % 20000) as u16,
            state: Some(TcpState::Established),
            pid: 100 + i % 3,
        }
    }

    #[tokio::test]
    async fn system_info_describes_the_agent() {
        let (client, _connector) = connect(EngineConfig::new("9.9.9", false)).await;
        let info: SystemInfo = client.request(method::SYSTEM_INFO, &()).await.unwrap();
        assert_eq!(info.agent_version, "9.9.9");
        assert_eq!(info.protocol_major, PROTOCOL_MAJOR);
        assert_eq!(info.pid, std::process::id());
        assert!(!info.service_mode);
        assert!(!info.hostname.is_empty());
        assert_eq!(client.agent().agent_version, "9.9.9");
    }

    #[tokio::test]
    async fn unknown_method_and_topic_are_typed_errors() {
        let (client, _connector) = connect(EngineConfig::new("1", true)).await;
        let err = client.request::<_, Value>("nope", &()).await.unwrap_err();
        assert!(matches!(err, ClientError::Remote(e) if e.code == ErrorCode::UnknownMethod));
        let err = client.subscribe("nope").await.err().unwrap();
        assert!(matches!(err, ClientError::Remote(e) if e.code == ErrorCode::UnknownTopic));
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_counts_up_once_per_interval() {
        let (client, _connector) = connect(EngineConfig::new("1", true)).await;
        let mut sub = client.subscribe(topic::LIVE_HEARTBEAT).await.unwrap();

        let first: Heartbeat = sub.recv_as().await.unwrap();
        assert_eq!(first.seq, 1);

        let before = Instant::now();
        let second: Heartbeat = sub.recv_as().await.unwrap();
        let third: Heartbeat = sub.recv_as().await.unwrap();
        assert_eq!((second.seq, third.seq), (2, 3));
        assert_eq!(
            before.elapsed(),
            Duration::from_secs(2),
            "one beat per second"
        );
        assert!(third.uptime_secs >= first.uptime_secs + 2);
        assert!(third.unix_ms >= first.unix_ms);
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_interval_is_configurable() {
        let mut config = EngineConfig::new("1", true);
        config.heartbeat_interval = Duration::from_millis(250);
        let (client, _connector) = connect(config).await;
        let mut sub = client.subscribe(topic::LIVE_HEARTBEAT).await.unwrap();
        let _: Heartbeat = sub.recv_as().await.unwrap();
        let before = Instant::now();
        let _: Heartbeat = sub.recv_as().await.unwrap();
        assert_eq!(before.elapsed(), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn each_subscription_starts_its_own_sequence_at_one() {
        let (client, _connector) = connect(EngineConfig::new("1", true)).await;
        let mut a = client.subscribe(topic::LIVE_HEARTBEAT).await.unwrap();
        let _: Heartbeat = a.recv_as().await.unwrap();
        let _: Heartbeat = a.recv_as().await.unwrap();
        client.unsubscribe(topic::LIVE_HEARTBEAT).await.unwrap();

        let mut b = client.subscribe(topic::LIVE_HEARTBEAT).await.unwrap();
        let first: Heartbeat = b.recv_as().await.unwrap();
        assert_eq!(first.seq, 1);
    }

    #[tokio::test]
    async fn live_stats_publishes_a_growing_sequence_with_the_current_state() {
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: vec![
                row("203.0.113.5", 0),
                row("203.0.113.5", 1),
                row("198.51.100.9", 2),
            ],
            processes: Default::default(),
        });
        let (client, _connector) =
            connect_with(fast(EngineConfig::new("1", true)), fake.clone()).await;
        let mut sub = client.subscribe(topic::LIVE_STATS).await.unwrap();

        let first: LiveStats = sub.recv_as().await.unwrap();
        let second: LiveStats = sub.recv_as().await.unwrap();
        assert!(second.seq > first.seq);
        assert_eq!(first.connections.total, 3);
        assert_eq!(first.top_remote[0].addr, "203.0.113.5");
        assert_eq!(first.top_remote[0].connections, 2);

        // A change in the OS shows up in a later snapshot.
        fake.set_connections(ConnectionTable {
            rows: vec![row("192.0.2.1", 9)],
            processes: Default::default(),
        });
        let mut seen_new_total = false;
        for _ in 0..20 {
            let stats: LiveStats = sub.recv_as().await.unwrap();
            if stats.connections.total == 1 {
                seen_new_total = true;
                break;
            }
        }
        assert!(seen_new_total, "the new connection table must be published");
    }

    #[tokio::test]
    async fn a_late_subscriber_gets_the_current_snapshot_immediately() {
        let mut config = EngineConfig::new("1", true);
        config.poll_interval = Duration::from_secs(3600); // only the very first poll happens
        let (client, _connector) = connect_with(config, Arc::new(FakeNetStat::new())).await;
        tokio::time::sleep(Duration::from_millis(150)).await; // let the first poll finish
        let mut sub = client.subscribe(topic::LIVE_STATS).await.unwrap();
        let stats = tokio::time::timeout(Duration::from_millis(500), sub.recv_as::<LiveStats>())
            .await
            .expect("must not wait a full poll interval")
            .unwrap();
        assert_eq!(stats.seq, 1);
    }

    async fn first_poll_done(client: &Client) -> ConnectionsResponse {
        for _ in 0..50 {
            let response: ConnectionsResponse = client
                .request(method::NETSTAT_CONNECTIONS, &ConnectionsRequest::default())
                .await
                .unwrap();
            if response.sampled_unix_ms > 0 {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the engine never published a snapshot");
    }

    #[tokio::test]
    async fn netstat_connections_returns_rows_and_only_the_needed_process_names() {
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: vec![row("203.0.113.5", 0), row("198.51.100.9", 1)],
            processes: [
                (100, "a.exe".to_owned()),
                (101, "b.exe".to_owned()),
                (999, "unused.exe".to_owned()),
            ]
            .into(),
        });
        let (client, _connector) = connect_with(fast(EngineConfig::new("1", true)), fake).await;
        let response = first_poll_done(&client).await;
        assert_eq!(response.connections.len(), 2);
        assert_eq!(response.total, 2);
        assert!(!response.truncated);
        assert_eq!(
            response.processes.len(),
            2,
            "names are sent once per PID in use"
        );
        assert_eq!(response.processes[&100], "a.exe");
        assert!(!response.processes.contains_key(&999));
    }

    #[tokio::test]
    async fn the_row_limit_truncates_and_reports_the_real_total() {
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: (0..500).map(|i| row("203.0.113.5", i)).collect(),
            processes: Default::default(),
        });
        let (client, _connector) = connect_with(fast(EngineConfig::new("1", true)), fake).await;
        first_poll_done(&client).await;
        let response: ConnectionsResponse = client
            .request(
                method::NETSTAT_CONNECTIONS,
                &ConnectionsRequest { limit: Some(100) },
            )
            .await
            .unwrap();
        assert_eq!(response.connections.len(), 100);
        assert_eq!(response.total, 500);
        assert!(response.truncated);
    }

    #[tokio::test]
    async fn a_huge_table_never_exceeds_the_frame_limit() {
        // A SYN flood: far more rows than fit in one frame. The reply must be cut, flagged and
        // still deliverable, never a frame the connection would reject.
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: (0..60_000)
                .map(|i| row("2001:0db8:85a3:0000:0000:8a2e:0370:7334", i))
                .collect(),
            processes: Default::default(),
        });
        let (client, _connector) = connect_with(fast(EngineConfig::new("1", true)), fake).await;
        first_poll_done(&client).await;
        let response: ConnectionsResponse = client
            .request(
                method::NETSTAT_CONNECTIONS,
                &ConnectionsRequest {
                    limit: Some(u32::MAX),
                },
            )
            .await
            .expect("the reply must fit in one frame");
        assert_eq!(response.total, 60_000);
        assert!(response.truncated);
        assert!(response.connections.len() <= pw_proto::DEFAULT_CONNECTION_LIMIT as usize);
        let size = serde_json::to_vec(&response).unwrap().len();
        assert!(size < MAX_FRAME_BYTES as usize, "{size} bytes");
    }

    #[tokio::test]
    async fn a_bad_connections_request_is_rejected() {
        let (client, _connector) = connect(EngineConfig::new("1", true)).await;
        let err = client
            .request::<_, Value>(
                method::NETSTAT_CONNECTIONS,
                &serde_json::json!({"limit": "many"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Remote(e) if e.code == ErrorCode::BadRequest));
    }

    #[tokio::test]
    async fn before_the_first_poll_the_connection_list_is_empty_not_an_error() {
        let mut config = EngineConfig::new("1", true);
        config.poll_interval = Duration::from_secs(3600);
        let engine = Engine::new(config, Arc::new(FakeNetStat::new()));
        // Ask before the poller task has had a chance to run.
        let reply = engine
            .handle(method::NETSTAT_CONNECTIONS, Value::Null)
            .await
            .unwrap();
        let response: ConnectionsResponse = serde_json::from_value(reply).unwrap();
        assert_eq!(response.total, 0);
        assert!(response.connections.is_empty());
    }

    async fn stats_until(
        sub: &mut pw_ipc::Subscription,
        ready: impl Fn(&LiveStats) -> bool,
    ) -> LiveStats {
        for _ in 0..100 {
            let stats: LiveStats = sub.recv_as().await.unwrap();
            if ready(&stats) {
                return stats;
            }
        }
        panic!("the expected stats never arrived");
    }

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;

    #[tokio::test]
    async fn live_stats_carries_the_rdp_trust_set_audit_and_feed_state() {
        use pw_netstat::logon::LogonEvent;
        use pw_proto::{AuditState, LogonAudit, TrustFeed};
        let now = poller::unix_ms();
        let fake = Arc::new(FakeNetStat::new());
        fake.set_logon_audit(LogonAudit {
            success: AuditState::Enabled,
            failure: AuditState::Disabled,
        });
        fake.set_logon_history(vec![
            LogonEvent {
                addr: "143.20.99.200".parse().unwrap(),
                at_unix_ms: now - 3 * DAY_MS,
            },
            LogonEvent {
                addr: "198.51.100.9".parse().unwrap(),
                at_unix_ms: now - 40 * DAY_MS,
            },
        ]);
        let (client, _connector) =
            connect_with(fast(EngineConfig::new("1", true)), fake.clone()).await;
        let mut sub = client.subscribe(topic::LIVE_STATS).await.unwrap();

        let stats = stats_until(&mut sub, |s| s.rdp_trust.feed == TrustFeed::Ready).await;
        let trust = &stats.rdp_trust;
        assert_eq!(trust.window_days, 30);
        assert_eq!(trust.audit.success, AuditState::Enabled);
        assert_eq!(trust.audit.failure, AuditState::Disabled);
        let addrs: Vec<&str> = trust.addresses.iter().map(|a| a.addr.as_str()).collect();
        assert_eq!(
            addrs,
            ["143.20.99.200"],
            "the 40-day-old logon is outside the window"
        );

        // A live event from the subscription shows up, most recent first.
        fake.push_logon(LogonEvent {
            addr: "203.0.113.7".parse().unwrap(),
            at_unix_ms: poller::unix_ms(),
        });
        let stats = stats_until(&mut sub, |s| s.rdp_trust.addresses.len() == 2).await;
        assert_eq!(stats.rdp_trust.addresses[0].addr, "203.0.113.7");
    }

    #[tokio::test]
    async fn an_unreadable_event_log_is_reported_and_trusts_nobody() {
        use pw_proto::TrustFeed;
        let fake = Arc::new(FakeNetStat::new());
        fake.set_logon_feed_unavailable(true);
        let (client, _connector) = connect_with(fast(EngineConfig::new("1", true)), fake).await;
        let mut sub = client.subscribe(topic::LIVE_STATS).await.unwrap();
        let stats = stats_until(&mut sub, |s| s.rdp_trust.feed != TrustFeed::Loading).await;
        assert_eq!(stats.rdp_trust.feed, TrustFeed::Unavailable);
        assert!(stats.rdp_trust.addresses.is_empty());
    }

    #[tokio::test]
    async fn the_trust_window_is_configurable_and_clamped() {
        let mut config = fast(EngineConfig::new("1", true));
        config.rdp_trust_days = 7;
        let (client, _connector) = connect_with(config, Arc::new(FakeNetStat::new())).await;
        let mut sub = client.subscribe(topic::LIVE_STATS).await.unwrap();
        assert_eq!(
            stats_until(&mut sub, |_| true).await.rdp_trust.window_days,
            7
        );

        let mut config = fast(EngineConfig::new("1", true));
        config.rdp_trust_days = 0; // nonsense: clamped to the minimum, never "trust nobody forever"
        let (client, _connector) = connect_with(config, Arc::new(FakeNetStat::new())).await;
        let mut sub = client.subscribe(topic::LIVE_STATS).await.unwrap();
        assert_eq!(
            stats_until(&mut sub, |_| true).await.rdp_trust.window_days,
            1
        );
    }
}
