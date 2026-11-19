// SPDX-License-Identifier: GPL-3.0-or-later
//! Diagnostics service (M3): long jobs (ping, MTR) that stream progress on the `diag.progress` topic,
//! and short requests (DNS lookup, port check, local ports). Wraps `pw-diag`.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use pw_diag::{
    format_report, mtr, ping, CancelToken, DnsClient, DnsLookup, DnsOptions, DnsRecordType,
    EchoStatus, FnSink, HickoryBackend, HopSnapshot, MtrOptions, MtrSnapshot, NameCache, NoReverse,
    PingOptions, PingReply, PingSummary, Pinger, PortCheck, PortCheckLimiter, PortProtocol,
    PortState, ReportContext, ResolverChoice, RttSummary,
};
use pw_proto::{
    DiagEvent, DiagStartResponse, DnsErrorView, DnsLookupRequest, DnsLookupView, DnsRecordView,
    EchoOutcome, ErrorCode, ErrorPayload, LocalPort, LocalPorts, MtrHopView, MtrReport,
    MtrStartRequest, MtrView, PingReplyView, PingStartRequest, PingSummaryView, PortCheckRequest,
    PortCheckView, PortStateView, Proto, RttView, TcpState,
};
use tokio::sync::{broadcast, mpsc};

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

struct Job {
    cancel: CancelToken,
    running: bool,
    target_text: String,
    last_mtr: Option<MtrSnapshot>,
}

#[derive(Default)]
struct Jobs {
    map: HashMap<u64, Job>,
    finished: VecDeque<u64>,
}

pub struct Diag<P> {
    pinger: Arc<P>,
    jobs: Arc<Mutex<Jobs>>,
    next_id: AtomicU64,
    events: broadcast::Sender<DiagEvent>,
    limiter: PortCheckLimiter,
    names: Option<Arc<NameCache<DnsClient<HickoryBackend>>>>,
}

impl<P: Pinger + 'static> Diag<P> {
    pub fn new(pinger: Arc<P>) -> Self {
        // Reverse lookups of hop addresses go to the system resolver only (never a third party).
        let names = DnsClient::with_options(&DnsOptions::default())
            .ok()
            .map(|client| Arc::new(NameCache::new(Arc::new(client), Duration::from_secs(2))));
        Self {
            pinger,
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
        let target = resolve_target(&request.target).await?;
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
        let resolve_names = request.resolve_names.unwrap_or(true);
        let (id, cancel) = self.register(&request.target)?;
        let pinger = Arc::clone(&self.pinger);
        let events = self.events.clone();
        let jobs = Arc::clone(&self.jobs);
        let names = self.names.clone().filter(|_| resolve_names);
        tokio::spawn(async move {
            let snapshots = events.clone();
            let store = Arc::clone(&jobs);
            let mut sink = FnSink(move |snapshot: MtrSnapshot| {
                if let Some(job) = lock(&store).map.get_mut(&id) {
                    job.last_mtr = Some(snapshot.clone());
                }
                let _ = snapshots.send(DiagEvent::MtrSnapshot {
                    job_id: id,
                    snapshot: mtr_view(&snapshot),
                });
            });
            let outcome = match &names {
                Some(cache) => mtr(pinger, target, &options, cache, &cancel, &mut sink).await,
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
            match outcome {
                Ok(last) => {
                    let _ = events.send(DiagEvent::MtrDone {
                        job_id: id,
                        cancelled: last.cancelled,
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
    /// public address when a XeroHost node told us; the line is omitted otherwise.
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
        let snapshot = job
            .last_mtr
            .as_ref()
            .ok_or_else(|| bad_request("this job has no MTR data yet"))?;
        let context = ReportContext {
            source_public_ip,
            generated_at: SystemTime::now(),
            target: job.target_text.clone(),
        };
        Ok(MtrReport {
            text: format_report(snapshot, &context),
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
        .find(|ip| ip.is_ipv4())
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
    }
}

pub fn mtr_view(snapshot: &MtrSnapshot) -> MtrView {
    MtrView {
        target: snapshot.target.to_string(),
        cycle: snapshot.cycle,
        total_cycles: snapshot.total_cycles,
        hops: snapshot.hops.iter().map(hop_view).collect(),
        destination_reached: snapshot.destination_reached,
        cancelled: snapshot.cancelled,
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
