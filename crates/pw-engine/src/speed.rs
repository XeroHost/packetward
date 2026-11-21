// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Speed test service (M9): one run at a time, streamed on the `speed.progress` topic. Wraps the
//! `pw-diag` speed client; the HTTP transport only exists with the `speed-http` feature (the agent
//! enables it), tests use the fake transport.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pw_diag::speed::{
    providers, BinOptions, BinResult, BinSize, Candidates, Direction, PickOptions, RunOptions,
    ServerEndpoint, SpeedClient, SpeedError, SpeedNode, SpeedPhase, SpeedProgress, SpeedResult,
    SpeedTransport, ThroughputOptions, ThroughputResult, UsageLedger,
};
use pw_diag::{CancelToken, FnSink};
use pw_proto::{
    ErrorCode, ErrorPayload, SpeedEvent, SpeedKind, SpeedLatencyView, SpeedRequest,
    SpeedResultView, SpeedServerView, SpeedStarted, SpeedTransferView,
};
use tokio::sync::{broadcast, mpsc};

const EVENT_BACKLOG: usize = 128;
const DEFAULT_STREAMS: u32 = 4;
const DEFAULT_DURATION_SECS: u32 = 10;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

/// What the engine needs from a speed test service (so it can hold one without being generic).
pub trait SpeedApi: Send + Sync {
    fn start(&self, request: SpeedRequest) -> Result<SpeedStarted, ErrorPayload>;
    fn cancel(&self, job_id: u64);
    fn subscribe(&self) -> mpsc::Receiver<serde_json::Value>;
}

/// Used when no HTTP transport was compiled in: every call says so clearly.
pub struct UnavailableSpeed;

impl SpeedApi for UnavailableSpeed {
    fn start(&self, _: SpeedRequest) -> Result<SpeedStarted, ErrorPayload> {
        Err(bad_request(
            "this build of the agent has no network transport for the speed test",
        ))
    }
    fn cancel(&self, _: u64) {}
    fn subscribe(&self) -> mpsc::Receiver<serde_json::Value> {
        mpsc::channel(1).1
    }
}

struct Running {
    id: u64,
    cancel: CancelToken,
}

pub struct SpeedService<T: SpeedTransport> {
    client: Arc<SpeedClient<T>>,
    nodes: Vec<SpeedNode>,
    state: Arc<Mutex<(u64, Option<Running>)>>,
    events: broadcast::Sender<SpeedEvent>,
}

impl<T: SpeedTransport + 'static> SpeedService<T> {
    /// `nodes` are the XeroHost nodes (an empty list is valid: only the user's own servers are used).
    pub fn new(transport: T, nodes: Vec<SpeedNode>) -> Self {
        Self {
            client: Arc::new(SpeedClient::with_ledger(
                Arc::new(transport),
                Arc::new(UsageLedger::new()),
            )),
            nodes,
            state: Arc::new(Mutex::new((0, None))),
            events: broadcast::channel(EVENT_BACKLOG).0,
        }
    }

    /// Events of every job; each subscriber filters by job id.
    pub fn events(&self) -> broadcast::Receiver<SpeedEvent> {
        self.events.subscribe()
    }
}

impl<T: SpeedTransport + 'static> SpeedApi for SpeedService<T> {
    fn start(&self, request: SpeedRequest) -> Result<SpeedStarted, ErrorPayload> {
        if request.servers.len() > 16 {
            return Err(bad_request("at most 16 custom servers"));
        }
        let provider = request.provider.as_deref().unwrap_or("auto");
        if !["auto", "xerohost", "custom"].contains(&provider)
            && !providers::GROUPS.contains(&provider)
        {
            return Err(bad_request("unknown speed-test provider"));
        }
        let mut candidates = match provider {
            "auto" => {
                let mut c = Candidates::from_lists(&self.nodes, &request.servers);
                // The public providers come last, so a tie in latency keeps XeroHost and the user's own.
                for server in providers::builtin_servers(None) {
                    if !c.servers.iter().any(|s| s.host == server.host) {
                        c.servers.push(server);
                    }
                }
                c
            }
            "xerohost" => Candidates::from_lists(&self.nodes, &[]),
            "custom" => Candidates::from_lists(&[], &request.servers),
            group => Candidates {
                servers: providers::builtin_servers(Some(group)),
                rejected: Vec::new(),
            },
        };
        // A bin test only goes to servers that offer that size (the public providers are limited so the
        // app does not hammer a free service).
        let bin_size = match request.kind {
            SpeedKind::Quick => None,
            SpeedKind::Bin1 => Some(BinSize::OneGib.bytes()),
            SpeedKind::Bin10 => Some(BinSize::TenGib.bytes()),
            SpeedKind::Bin50 => Some(BinSize::FiftyGib.bytes()),
        };
        if let Some(size) = bin_size {
            let before = candidates.servers.len();
            candidates
                .servers
                .retain(|s| s.bin_limit_bytes().is_none_or(|limit| limit >= size));
            if candidates.servers.is_empty() && before > 0 {
                return Err(bad_request(
                    "no server of this provider offers a test this large: use Hetzner for up to 10 GB, or XeroHost / your own server",
                ));
            }
        }
        let rejected: Vec<String> = candidates
            .rejected
            .iter()
            .map(|r| format!("#{}: {}", r.index + 1, r.reason))
            .collect();
        if candidates.servers.is_empty() {
            return Err(bad_request(
                "no speed-test server for this choice: pick a public provider, add your own speed-server, or wait for the XeroHost nodes",
            ));
        }
        let cancel = CancelToken::new();
        let id = {
            let mut state = lock(&self.state);
            if state.1.is_some() {
                return Err(ErrorPayload::new(
                    ErrorCode::Busy,
                    "a speed test is already running",
                ));
            }
            state.0 += 1;
            let id = state.0;
            state.1 = Some(Running {
                id,
                cancel: cancel.clone(),
            });
            id
        };
        let client = Arc::clone(&self.client);
        let events = self.events.clone();
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let outcome =
                run_job(&client, id, &request, &candidates.servers, &cancel, &events).await;
            // Free the slot before announcing the end, so a client may start the next one at once.
            {
                let mut guard = lock(&state);
                if guard.1.as_ref().is_some_and(|r| r.id == id) {
                    guard.1 = None;
                }
            }
            let _ = events.send(match outcome {
                Ok(result) => SpeedEvent::Done {
                    job_id: id,
                    result: Box::new(result),
                },
                Err(err) => failed(id, &err),
            });
        });
        Ok(SpeedStarted {
            job_id: id,
            rejected,
        })
    }

    fn cancel(&self, job_id: u64) {
        if let Some(running) = lock(&self.state).1.as_ref().filter(|r| r.id == job_id) {
            running.cancel.cancel();
        }
    }

    fn subscribe(&self) -> mpsc::Receiver<serde_json::Value> {
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
}

fn failed(job_id: u64, err: &SpeedError) -> SpeedEvent {
    let (code, retry_after_secs) = match err {
        SpeedError::Cancelled => ("cancelled", None),
        SpeedError::NoServer => ("no_server", None),
        SpeedError::ConfirmationRequired { .. } => ("confirmation_required", None),
        SpeedError::RateLimited { retry_after_secs } => ("rate_limited", *retry_after_secs),
        SpeedError::BudgetExceeded { .. } => ("budget_exceeded", None),
        SpeedError::Server { .. } => ("server", None),
        SpeedError::InvalidInput(_) => ("invalid", None),
        SpeedError::Incomplete { .. } => ("incomplete", None),
        _ => ("transport", None),
    };
    SpeedEvent::Failed {
        job_id,
        code: code.to_owned(),
        message: err.to_string(),
        retry_after_secs,
    }
}

fn phase_name(phase: SpeedPhase) -> &'static str {
    match phase {
        SpeedPhase::PickingServer => "picking_server",
        SpeedPhase::ServerInfo => "server_info",
        SpeedPhase::Latency => "latency",
        SpeedPhase::Download => "download",
        SpeedPhase::Upload => "upload",
        SpeedPhase::BinDownload => "bin_download",
    }
}

fn progress_event(job_id: u64, progress: SpeedProgress) -> SpeedEvent {
    match progress {
        SpeedProgress::Phase { phase } => SpeedEvent::Phase {
            job_id,
            phase: phase_name(phase).to_owned(),
        },
        SpeedProgress::Ping { seq, rtt_ms } => SpeedEvent::Ping {
            job_id,
            seq,
            rtt_ms,
        },
        SpeedProgress::Throughput {
            direction,
            elapsed_ms,
            warmup,
            mbps,
            avg_mbps,
            ..
        } => SpeedEvent::Rate {
            job_id,
            direction: match direction {
                Direction::Download => "download",
                Direction::Upload => "upload",
            }
            .to_owned(),
            elapsed_ms,
            warmup,
            mbps,
            avg_mbps,
        },
        SpeedProgress::Bin {
            bytes_done,
            bytes_total,
            mbps,
            avg_mbps,
            elapsed_ms,
        } => SpeedEvent::Bin {
            job_id,
            bytes_done,
            bytes_total,
            mbps,
            avg_mbps,
            elapsed_ms,
        },
    }
}

async fn run_job<T: SpeedTransport + 'static>(
    client: &SpeedClient<T>,
    job_id: u64,
    request: &SpeedRequest,
    servers: &[ServerEndpoint],
    cancel: &CancelToken,
    events: &broadcast::Sender<SpeedEvent>,
) -> Result<SpeedResultView, SpeedError> {
    let tx = events.clone();
    let mut sink = FnSink(move |progress: SpeedProgress| {
        let _ = tx.send(progress_event(job_id, progress));
    });
    let streams = request.streams.unwrap_or(DEFAULT_STREAMS).clamp(1, 16) as usize;
    match request.kind {
        SpeedKind::Quick => {
            let seconds = u64::from(
                request
                    .duration_secs
                    .unwrap_or(DEFAULT_DURATION_SECS)
                    .clamp(1, 120),
            );
            let throughput = ThroughputOptions {
                streams,
                duration: Duration::from_secs(seconds),
                ..ThroughputOptions::default()
            };
            let options = RunOptions {
                download: Some(throughput.clone()),
                upload: Some(throughput),
                ..RunOptions::default()
            };
            let result = client.run(servers, &options, cancel, &mut sink).await?;
            Ok(quick_view(request.kind, &result))
        }
        SpeedKind::Bin1 | SpeedKind::Bin10 | SpeedKind::Bin50 => {
            let size = match request.kind {
                SpeedKind::Bin1 => BinSize::OneGib,
                SpeedKind::Bin10 => BinSize::TenGib,
                _ => BinSize::FiftyGib,
            };
            let options = BinOptions {
                confirm_large: request.confirm_large,
                streams,
                ..BinOptions::new(size)
            };
            // The confirmation is checked before any traffic, including the server probe.
            if size.needs_confirmation() && !options.confirm_large {
                return Err(SpeedError::ConfirmationRequired {
                    size_bytes: size.bytes(),
                });
            }
            let picked = client
                .pick_server(servers, &PickOptions::default(), cancel)
                .await?;
            let server = picked.best().ok_or(SpeedError::NoServer)?.clone();
            let info = client.server_info(&server, cancel).await.ok();
            let bin = client
                .bin_test(&server, info.as_ref(), &options, cancel, &mut sink)
                .await?;
            let source_ip = info
                .as_ref()
                .and_then(|i| i.client_ip.parse::<std::net::IpAddr>().ok());
            Ok(bin_view(
                request.kind,
                &picked.probes,
                &server,
                info.as_ref(),
                source_ip,
                &bin,
            ))
        }
    }
}

fn server_view(
    endpoint: &ServerEndpoint,
    latency_ms: Option<f64>,
    name: Option<&str>,
    location: Option<&str>,
) -> SpeedServerView {
    SpeedServerView {
        id: endpoint.id.clone(),
        name: name.unwrap_or(&endpoint.name).to_owned(),
        location: location.map(str::to_owned),
        latency_ms,
        custom: endpoint.custom,
        provider: providers::builtin_of(endpoint).map(|b| b.group.to_owned()),
    }
}

fn transfer_view(t: &ThroughputResult) -> SpeedTransferView {
    SpeedTransferView {
        streams: t.streams,
        avg_mbps: t.avg_mbps,
        peak_mbps: t.peak_mbps,
        bytes: t.bytes,
        duration_ms: t.duration_ms,
        buckets_mbps: t.buckets_mbps.clone(),
    }
}

fn quick_view(kind: SpeedKind, result: &SpeedResult) -> SpeedResultView {
    SpeedResultView {
        started_unix_ms: result.started_at_unix_ms,
        kind,
        server: SpeedServerView {
            id: result.server.id.clone(),
            name: result.server.name.clone(),
            location: result.server.location.clone(),
            latency_ms: result
                .servers_probed
                .iter()
                .find(|p| p.server.id == result.server.id)
                .and_then(|p| p.latency_ms),
            custom: result.server.custom,
            provider: result.server.provider.clone(),
        },
        candidates: result
            .servers_probed
            .iter()
            .map(|p| server_view(&p.server, p.latency_ms, None, None))
            .collect(),
        source_ip: result.source_ip.map(|ip| ip.to_string()),
        latency: result.latency.as_ref().map(|l| SpeedLatencyView {
            sent: l.sent,
            received: l.received,
            loss_percent: l.loss_percent,
            min_ms: l.min_ms,
            avg_ms: l.avg_ms,
            max_ms: l.max_ms,
            jitter_ms: l.jitter_ms,
        }),
        download: result.download.as_ref().map(transfer_view),
        upload: result.upload.as_ref().map(transfer_view),
        upload_server: result.upload_server.as_ref().map(|s| SpeedServerView {
            id: s.id.clone(),
            name: s.name.clone(),
            location: s.location.clone(),
            latency_ms: result
                .servers_probed
                .iter()
                .find(|p| p.server.id == s.id)
                .and_then(|p| p.latency_ms),
            custom: s.custom,
            provider: s.provider.clone(),
        }),
    }
}

fn bin_view(
    kind: SpeedKind,
    probes: &[pw_diag::speed::ServerProbe],
    server: &ServerEndpoint,
    info: Option<&pw_diag::speed::ServerInfo>,
    source_ip: Option<std::net::IpAddr>,
    bin: &BinResult,
) -> SpeedResultView {
    let latency = probes
        .iter()
        .find(|p| p.server.id == server.id)
        .and_then(|p| p.latency_ms);
    let name = info.map(|i| i.node_name.as_str()).filter(|n| !n.is_empty());
    let location = info.map(|i| i.location.as_str()).filter(|n| !n.is_empty());
    SpeedResultView {
        started_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .saturating_sub(bin.duration_ms),
        kind,
        server: server_view(server, latency, name, location),
        candidates: probes
            .iter()
            .map(|p| server_view(&p.server, p.latency_ms, None, None))
            .collect(),
        source_ip: source_ip.map(|ip| ip.to_string()),
        latency: None,
        download: Some(SpeedTransferView {
            streams: bin.streams,
            avg_mbps: bin.avg_mbps,
            peak_mbps: bin.peak_mbps,
            bytes: bin.bytes,
            duration_ms: bin.duration_ms,
            buckets_mbps: bin.buckets_mbps.clone(),
        }),
        upload: None,
        upload_server: None,
    }
}

#[cfg(test)]
mod tests {
    use pw_diag::speed::fake::FakeTransport;
    use pw_diag::speed::{ServerInfo, ServerLimits};

    use super::*;

    fn info() -> ServerInfo {
        ServerInfo {
            protocol: 1,
            server_version: "1".into(),
            node_id: "mia".into(),
            node_name: "Miami".into(),
            location: "Miami, US".into(),
            client_ip: "203.0.113.9".into(),
            max_download_bytes: 50 * 1024 * 1024 * 1024,
            max_upload_bytes: 10 * 1024 * 1024 * 1024,
            limits: ServerLimits::default(),
        }
    }

    fn service(fast: bool) -> (SpeedService<FakeTransport>, FakeTransport) {
        let fake = FakeTransport::new();
        fake.set_latency("speed.example.test:443", Duration::from_millis(7));
        fake.set_info("speed.example.test:443", Ok(info()));
        if fast {
            fake.set_rate(50_000_000);
        }
        (SpeedService::new(fake.clone(), Vec::new()), fake)
    }

    fn request(kind: SpeedKind) -> SpeedRequest {
        SpeedRequest {
            kind,
            servers: vec!["speed.example.test".into()],
            provider: Some("custom".into()),
            streams: Some(2),
            duration_secs: Some(1),
            confirm_large: false,
        }
    }

    async fn finish(events: &mut broadcast::Receiver<SpeedEvent>) -> SpeedEvent {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let event = events.recv().await.unwrap();
                if matches!(event, SpeedEvent::Done { .. } | SpeedEvent::Failed { .. }) {
                    return event;
                }
            }
        })
        .await
        .expect("the run ends")
    }

    #[tokio::test]
    async fn a_quick_test_streams_progress_and_reports_the_source_ip() {
        let (service, _fake) = service(true);
        let mut events = service.events();
        let started = service.start(request(SpeedKind::Quick)).unwrap();
        let mut saw_phase = false;
        let done = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match events.recv().await.unwrap() {
                    SpeedEvent::Phase { .. } => saw_phase = true,
                    event @ (SpeedEvent::Done { .. } | SpeedEvent::Failed { .. }) => return event,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        assert!(saw_phase);
        let SpeedEvent::Done { job_id, result } = done else {
            panic!("expected a result: {done:?}");
        };
        assert_eq!(job_id, started.job_id);
        assert_eq!(result.server.name, "Miami");
        assert_eq!(result.source_ip.as_deref(), Some("203.0.113.9"));
        assert!(result.latency.as_ref().unwrap().received > 0);
        assert!(result.download.as_ref().unwrap().avg_mbps > 0.0);
        assert!(result.upload.is_some());
    }

    #[tokio::test]
    async fn no_servers_and_bad_addresses_are_explained_before_anything_runs() {
        let (service, fake) = service(false);
        let none = SpeedRequest {
            servers: vec![],
            ..request(SpeedKind::Quick)
        };
        let err = service.start(none).unwrap_err();
        assert!(err.message.contains("no speed-test server"));
        let bad = SpeedRequest {
            servers: vec![
                "REPLACE-WITH-REAL-HOSTNAME".into(),
                "ok.example.test".into(),
            ],
            ..request(SpeedKind::Quick)
        };
        let started = service.start(bad).unwrap();
        assert_eq!(started.rejected.len(), 1);
        service.cancel(started.job_id);
        assert!(fake.bytes_moved() < 5_000_000);
    }

    /// The whole path with the real transport and no configured server: the automatic choice picks a public
    /// provider and measures it. A few seconds of traffic. Run on purpose:
    /// `cargo test -p pw-engine --features net-http --lib live_automatic -- --ignored --nocapture`.
    #[cfg(feature = "net-http")]
    #[tokio::test]
    #[ignore = "uses the public internet"]
    async fn live_automatic_quick_test_with_no_server_configured() {
        use pw_diag::speed::{HttpTransport, HttpTransportConfig};
        let transport = HttpTransport::new(&HttpTransportConfig::default()).unwrap();
        let service = SpeedService::new(transport, Vec::new());
        let mut events = service.events();
        let started = service
            .start(SpeedRequest {
                kind: SpeedKind::Quick,
                servers: vec![],
                provider: None,
                streams: Some(2),
                duration_secs: Some(3),
                confirm_large: false,
            })
            .unwrap();
        let done = loop {
            match tokio::time::timeout(Duration::from_secs(90), events.recv())
                .await
                .unwrap()
                .unwrap()
            {
                SpeedEvent::Done { job_id, result } if job_id == started.job_id => break result,
                SpeedEvent::Failed {
                    job_id, message, ..
                } if job_id == started.job_id => {
                    panic!("failed: {message}")
                }
                _ => {}
            }
        };
        println!(
            "server {} ({:?}), download {:?}, upload {:?} on {:?}, latency {:?}",
            done.server.name,
            done.server.provider,
            done.download.as_ref().map(|d| d.avg_mbps),
            done.upload.as_ref().map(|u| u.avg_mbps),
            done.upload_server.as_ref().map(|s| s.name.clone()),
            done.latency.as_ref().map(|l| l.avg_ms),
        );
        assert!(done.download.is_some_and(|d| d.avg_mbps > 0.0));
        assert!(
            done.upload.is_some(),
            "an upload-capable provider exists in the candidates"
        );
    }

    /// Each public provider on its own, with the real transport: the rate limits of the free mirrors must not
    /// end a quick test. About 15 s per provider. Run on purpose:
    /// cargo test -p pw-engine --features net-http --lib live_each_provider -- --ignored --nocapture
    #[cfg(feature = "net-http")]
    #[tokio::test]
    #[ignore = "uses the public internet"]
    async fn live_each_provider_completes_a_quick_test() {
        use pw_diag::speed::{HttpTransport, HttpTransportConfig};
        for group in ["cloudflare", "hetzner", "ovh"] {
            let transport = HttpTransport::new(&HttpTransportConfig::default()).unwrap();
            let service = SpeedService::new(transport, Vec::new());
            let mut events = service.events();
            let started = service
                .start(SpeedRequest {
                    kind: SpeedKind::Quick,
                    servers: vec![],
                    provider: Some(group.into()),
                    streams: Some(4),
                    duration_secs: Some(4),
                    confirm_large: false,
                })
                .unwrap();
            let outcome = loop {
                match tokio::time::timeout(Duration::from_secs(120), events.recv())
                    .await
                    .unwrap()
                    .unwrap()
                {
                    SpeedEvent::Done { job_id, result } if job_id == started.job_id => {
                        break Ok(result)
                    }
                    SpeedEvent::Failed {
                        job_id, message, ..
                    } if job_id == started.job_id => break Err(message),
                    _ => {}
                }
            };
            match outcome {
                Ok(done) => println!(
                    "{group}: {} down {:?} Mbps ({} streams), up {:?} on {:?}, latency {:?} ms",
                    done.server.name,
                    done.download.as_ref().map(|d| d.avg_mbps),
                    done.download.as_ref().map_or(0, |d| d.streams),
                    done.upload.as_ref().map(|u| u.avg_mbps),
                    done.upload_server.as_ref().map(|s| s.name.clone()),
                    done.latency.as_ref().map(|l| l.avg_ms),
                ),
                Err(message) => panic!("{group} failed: {message}"),
            }
            // Be kind to the free services between providers.
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    #[tokio::test]
    async fn the_public_providers_make_the_test_work_with_no_server_configured() {
        let (service, _fake) = service(false);
        // No custom server, no XeroHost node: the default choice still has somewhere to go.
        let auto = SpeedRequest {
            servers: vec![],
            provider: None,
            ..request(SpeedKind::Quick)
        };
        let started = service.start(auto).unwrap();
        service.cancel(started.job_id);
        // A provider can be chosen by name.
        for group in ["cloudflare", "hetzner", "ovh"] {
            // Wait for the previous job's slot (the fake has no such host: the run fails fast).
            let mut events = service.events();
            let request = SpeedRequest {
                servers: vec![],
                provider: Some(group.into()),
                ..request(SpeedKind::Quick)
            };
            let started = loop {
                match service.start(request.clone()) {
                    Ok(started) => break started,
                    Err(err) if err.code == ErrorCode::Busy => {
                        let _ = tokio::time::timeout(Duration::from_secs(5), events.recv()).await;
                    }
                    Err(err) => panic!("{group}: {err:?}"),
                }
            };
            service.cancel(started.job_id);
        }
    }

    #[tokio::test]
    async fn an_unknown_provider_and_empty_choices_are_explained() {
        let (service, _fake) = service(false);
        let unknown = SpeedRequest {
            provider: Some("nope".into()),
            ..request(SpeedKind::Quick)
        };
        assert!(service
            .start(unknown)
            .unwrap_err()
            .message
            .contains("unknown speed-test provider"));
        // XeroHost has no node yet and custom has no address: nothing to run against.
        for (provider, servers) in [("xerohost", vec![]), ("custom", vec![])] {
            let request = SpeedRequest {
                provider: Some(provider.into()),
                servers,
                ..request(SpeedKind::Quick)
            };
            assert!(service
                .start(request)
                .unwrap_err()
                .message
                .contains("no speed-test server"));
        }
    }

    #[tokio::test]
    async fn bin_tests_only_go_to_providers_that_offer_the_size() {
        let (service, fake) = service(false);
        for (provider, kind, allowed) in [
            ("cloudflare", SpeedKind::Bin1, false),
            ("ovh", SpeedKind::Bin1, true),
            ("ovh", SpeedKind::Bin10, false),
            ("hetzner", SpeedKind::Bin10, true),
        ] {
            let request = SpeedRequest {
                servers: vec![],
                provider: Some(provider.into()),
                ..request(kind)
            };
            let outcome = service.start(request);
            if allowed {
                let started = outcome.unwrap_or_else(|e| panic!("{provider}: {e:?}"));
                service.cancel(started.job_id);
                // Let the slot free up before the next case.
                tokio::time::sleep(Duration::from_millis(200)).await;
            } else {
                assert!(
                    outcome
                        .unwrap_err()
                        .message
                        .contains("offers a test this large"),
                    "{provider} must refuse {kind:?}"
                );
            }
        }
        assert!(fake.bytes_moved() < 5_000_000);
    }

    #[tokio::test]
    async fn only_one_test_runs_at_a_time_and_it_can_be_cancelled() {
        let (service, _fake) = service(false);
        let mut events = service.events();
        let first = service.start(request(SpeedKind::Quick)).unwrap();
        let busy = service.start(request(SpeedKind::Quick)).unwrap_err();
        assert_eq!(busy.code, ErrorCode::Busy);
        service.cancel(first.job_id);
        let ended = finish(&mut events).await;
        let SpeedEvent::Failed { code, .. } = ended else {
            panic!("expected a cancellation: {ended:?}");
        };
        assert_eq!(code, "cancelled");
        // The slot is free again.
        assert!(service.start(request(SpeedKind::Quick)).is_ok());
    }

    #[tokio::test]
    async fn the_50_gib_test_needs_the_confirmation_before_any_traffic() {
        let (service, fake) = service(false);
        let mut events = service.events();
        service.start(request(SpeedKind::Bin50)).unwrap();
        let SpeedEvent::Failed { code, .. } = finish(&mut events).await else {
            panic!("expected a refusal");
        };
        assert_eq!(code, "confirmation_required");
        assert_eq!(fake.bytes_moved(), 0);
    }

    #[tokio::test]
    async fn an_unavailable_transport_says_so() {
        let err = UnavailableSpeed
            .start(request(SpeedKind::Quick))
            .unwrap_err();
        assert!(err.message.contains("no network transport"));
    }

    #[tokio::test]
    async fn a_dead_server_is_a_clear_failure() {
        let fake = FakeTransport::new(); // nothing answers
        let service = SpeedService::new(fake, Vec::new());
        let mut events = service.events();
        service.start(request(SpeedKind::Quick)).unwrap();
        let SpeedEvent::Failed { code, .. } = finish(&mut events).await else {
            panic!("expected a failure");
        };
        assert_eq!(code, "no_server");
    }
}
