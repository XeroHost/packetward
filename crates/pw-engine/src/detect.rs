// SPDX-License-Identifier: GPL-3.0-or-later
//! Detection service (M5): feeds `pw-detect` from every input that exists, ticks it once a second
//! and keeps the resulting alerts (bounded, persisted as JSON lines, pushed to subscribers).
//!
//! Detection must not depend on capture alone (the raw-socket backend can be blind): connection
//! counts come from netstat, bandwidth from the adapter counters and RDP brute force from the
//! failed-logon feed. Capture only adds the SYN/UDP/ICMP flood and scan detectors.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use pw_core::{CidrSet, PacketMeta};
use pw_detect::{
    Alert, AlertPhase, Config, ConnectionCounts, DetectorKind, Engine as Detector, Preset, Severity,
};
use pw_netstat::logon::LogonEvent;
use pw_proto::{
    AlertKindView, AlertList, AlertMetric, AlertPhaseView, AlertSeverity, AlertView, Proto,
    TcpState,
};
use tokio::sync::{broadcast, mpsc};

use crate::poller::Snapshot;

/// Incidents kept in memory (and reloaded from disk at start).
pub const KEEP_INCIDENTS: usize = 500;
const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
const EVENT_BACKLOG: usize = 64;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

// ---- conversions ----------------------------------------------------------------------------------

fn severity_view(severity: Severity) -> AlertSeverity {
    match severity {
        Severity::Low => AlertSeverity::Low,
        Severity::Medium => AlertSeverity::Medium,
        Severity::High => AlertSeverity::High,
        Severity::Critical => AlertSeverity::Critical,
    }
}

fn kind_view(kind: DetectorKind) -> AlertKindView {
    match kind {
        DetectorKind::SynFlood => AlertKindView::SynFlood,
        DetectorKind::UdpFlood => AlertKindView::UdpFlood,
        DetectorKind::IcmpFlood => AlertKindView::IcmpFlood,
        DetectorKind::PortScan => AlertKindView::PortScan,
        DetectorKind::ConnFlood => AlertKindView::ConnFlood,
        DetectorKind::RdpBruteForce => AlertKindView::RdpBruteForce,
        DetectorKind::Aggregate => AlertKindView::Aggregate,
    }
}

/// An alert of the detector as the wire type. `peak` is filled in by the store.
pub fn alert_view(alert: &Alert) -> AlertView {
    let severity = severity_view(alert.severity);
    AlertView {
        id: alert.id,
        phase: match alert.phase {
            AlertPhase::Started => AlertPhaseView::Started,
            AlertPhase::Escalated => AlertPhaseView::Escalated,
            AlertPhase::Ended => AlertPhaseView::Ended,
        },
        kind: kind_view(alert.kind),
        severity,
        source: alert.source.map(|ip| ip.to_string()),
        summary_key: alert.summary_key.to_owned(),
        metrics: alert
            .metrics
            .iter()
            .map(|m| AlertMetric {
                key: m.key.to_owned(),
                value: m.value,
            })
            .collect(),
        window_secs: alert.window_secs,
        first_seen_unix_ms: alert.first_seen_ns / 1_000_000,
        last_seen_unix_ms: alert.last_seen_ns / 1_000_000,
        protected: alert.protected,
        peak_severity: severity,
    }
}

// ---- the store ------------------------------------------------------------------------------------

struct StoreInner {
    /// Newest first, one entry per incident id.
    incidents: VecDeque<AlertView>,
    dropped: u64,
    log: Option<PathBuf>,
}

/// Bounded list of incidents, persisted as JSON lines so the inbox survives an agent restart.
pub struct AlertStore {
    inner: Mutex<StoreInner>,
    events: broadcast::Sender<AlertView>,
}

impl AlertStore {
    /// `log` is the JSON-lines file (created on first write); existing lines are reloaded.
    pub fn new(log: Option<PathBuf>) -> Self {
        let mut incidents: VecDeque<AlertView> = VecDeque::new();
        if let Some(path) = &log {
            if let Ok(text) = fs::read_to_string(path) {
                for line in text.lines() {
                    if let Ok(event) = serde_json::from_str::<AlertView>(line) {
                        apply(&mut incidents, event);
                    }
                }
                while incidents.len() > KEEP_INCIDENTS {
                    incidents.pop_back();
                }
                // An incident that was still running when the agent stopped is over now.
                for incident in &mut incidents {
                    if incident.phase != AlertPhaseView::Ended {
                        incident.phase = AlertPhaseView::Ended;
                    }
                }
            }
        }
        Self {
            inner: Mutex::new(StoreInner {
                incidents,
                dropped: 0,
                log,
            }),
            events: broadcast::channel(EVENT_BACKLOG).0,
        }
    }

    pub fn record(&self, event: AlertView) {
        let stored = {
            let mut inner = lock(&self.inner);
            let stored = apply(&mut inner.incidents, event);
            while inner.incidents.len() > KEEP_INCIDENTS {
                inner.incidents.pop_back();
                inner.dropped += 1;
            }
            if let Some(path) = inner.log.clone() {
                append_line(&path, &stored);
            }
            stored
        };
        let _ = self.events.send(stored);
    }

    pub fn list(&self) -> AlertList {
        let inner = lock(&self.inner);
        AlertList {
            alerts: inner.incidents.iter().cloned().collect(),
            dropped: inner.dropped,
        }
    }

    /// Removes the incidents that ended; ongoing ones stay. Returns how many went.
    pub fn clear_ended(&self) -> usize {
        let mut inner = lock(&self.inner);
        let before = inner.incidents.len();
        inner.incidents.retain(|i| i.phase != AlertPhaseView::Ended);
        let removed = before - inner.incidents.len();
        if let Some(path) = inner.log.clone() {
            // Rewrite the log with what is left, so cleared alerts do not come back after a restart.
            let lines: String = inner
                .incidents
                .iter()
                .rev()
                .filter_map(|i| serde_json::to_string(i).ok())
                .map(|l| l + "\n")
                .collect();
            let _ = fs::write(path, lines);
        }
        removed
    }

    /// Every change of an incident, as it happens.
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
}

/// Merges one update into the list (newest first) and returns the stored incident.
fn apply(incidents: &mut VecDeque<AlertView>, mut event: AlertView) -> AlertView {
    if let Some(position) = incidents.iter().position(|i| i.id == event.id) {
        if let Some(existing) = incidents.remove(position) {
            event.first_seen_unix_ms = existing.first_seen_unix_ms;
            event.peak_severity = existing.peak_severity.max(event.severity);
            if event.phase == AlertPhaseView::Ended {
                // An ended incident keeps the severity it peaked at.
                event.severity = event.peak_severity;
            }
        }
    }
    incidents.push_front(event.clone());
    event
}

fn append_line(path: &PathBuf, event: &AlertView) {
    let Ok(line) = serde_json::to_string(event) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::metadata(path).is_ok_and(|m| m.len() > LOG_MAX_BYTES) {
        let _ = fs::rename(path, path.with_extension("jsonl.1"));
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

// ---- the service ----------------------------------------------------------------------------------

/// What the netstat snapshot says about remote addresses, and how it differs from the last one.
#[derive(Default)]
struct ConnectionDiff {
    previous: HashSet<(IpAddr, u16, u16)>,
}

impl ConnectionDiff {
    /// Per remote address: TCP connections right now, and how many were not there a second ago.
    fn counts(&mut self, snapshot: &Snapshot) -> Vec<(IpAddr, ConnectionCounts)> {
        let mut current: HashSet<(IpAddr, u16, u16)> = HashSet::new();
        let mut per_ip: HashMap<IpAddr, (u32, u32)> = HashMap::new();
        for row in &snapshot.table.rows {
            if row.proto != Proto::Tcp
                || matches!(
                    row.state,
                    Some(TcpState::Listen | TcpState::TimeWait) | None
                )
            {
                continue;
            }
            let Ok(ip) = row.remote_addr.parse::<IpAddr>() else {
                continue;
            };
            let ip = ip.to_canonical();
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            let key = (ip, row.local_port, row.remote_port);
            let is_new = !self.previous.contains(&key);
            let entry = per_ip.entry(ip).or_default();
            entry.0 += 1;
            if is_new {
                entry.1 += 1;
            }
            current.insert(key);
        }
        // The very first snapshot has nothing to compare with: every row would look new.
        let first = self.previous.is_empty();
        self.previous = current;
        per_ip
            .into_iter()
            .map(|(ip, (concurrent, new))| {
                (
                    ip,
                    ConnectionCounts {
                        concurrent,
                        new: if first { 0 } else { new },
                    },
                )
            })
            .collect()
    }
}

pub struct DetectionService {
    detector: Mutex<Detector>,
    diff: Mutex<ConnectionDiff>,
    store: Arc<AlertStore>,
}

impl DetectionService {
    pub fn new(preset: Preset, store: Arc<AlertStore>) -> Self {
        Self {
            detector: Mutex::new(Detector::new(Config::preset(preset))),
            diff: Mutex::new(ConnectionDiff::default()),
            store,
        }
    }

    pub fn store(&self) -> &Arc<AlertStore> {
        &self.store
    }

    /// Every captured batch (called on the engine's capture task: must stay quick).
    pub fn ingest(&self, batch: &[PacketMeta]) {
        let mut detector = lock(&self.detector);
        for packet in batch {
            detector.ingest(packet);
        }
    }

    /// A failed remote logon (Security 4625).
    pub fn logon_failure(&self, event: LogonEvent) {
        lock(&self.detector)
            .observe_logon_failure(event.addr, event.at_unix_ms.saturating_mul(1_000_000));
    }

    /// Sources that must be flagged `protected` (trusted RDP clients, allowlist…).
    pub fn set_protected(&self, protected: CidrSet) {
        lock(&self.detector).set_protected(protected);
    }

    /// One second of the netstat-based inputs, then the detectors' own tick. Returns how many alert
    /// events were produced.
    pub fn tick(&self, snapshot: Option<&Snapshot>, now_ns: u64) -> usize {
        let alerts = {
            let mut detector = lock(&self.detector);
            if let Some(snapshot) = snapshot {
                let rows = lock(&self.diff).counts(snapshot);
                detector.observe_connection_counts(now_ns, rows);
                let totals = &snapshot.stats.totals;
                let link = snapshot
                    .stats
                    .interfaces
                    .iter()
                    .filter(|i| i.counts_toward_total)
                    .map(|i| i.link_speed_bps)
                    .max()
                    .unwrap_or(0);
                detector.observe_inbound_bps(now_ns, totals.in_bps.max(0.0) as u64, link);
            }
            detector.tick(now_ns)
        };
        let produced = alerts.len();
        for alert in &alerts {
            self.store.record(alert_view(alert));
        }
        produced
    }
}

/// A trusted-address `CidrSet` for the detector's `protected` flag.
pub fn protected_from(addresses: &[String]) -> CidrSet {
    let mut set = CidrSet::new();
    for addr in addresses {
        let _ = set.insert_str(addr);
    }
    set
}

pub fn tick_now(service: &DetectionService, snapshot: Option<&Snapshot>) -> usize {
    service.tick(snapshot, now_ns())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pw_detect::testgen;
    use pw_netstat::ConnectionTable;
    use pw_proto::Connection;

    use super::*;

    fn service() -> DetectionService {
        DetectionService::new(Preset::Balanced, Arc::new(AlertStore::new(None)))
    }

    fn snapshot_with(rows: Vec<Connection>) -> Snapshot {
        use crate::poller::Poller;
        use pw_netstat::fake::FakeNetStat;
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows,
            processes: Default::default(),
        });
        Poller::new(fake, 5, crate::trust::TrustState::new(30)).poll(std::time::Instant::now(), 1)
    }

    fn conn(remote: &str, i: u32) -> Connection {
        Connection {
            proto: Proto::Tcp,
            local_addr: "10.0.0.5".into(),
            local_port: 443,
            remote_addr: remote.into(),
            remote_port: 40_000 + i as u16,
            state: Some(TcpState::Established),
            pid: 1,
        }
    }

    #[test]
    fn a_connection_flood_from_netstat_alone_raises_an_incident() {
        let svc = service();
        let rows: Vec<Connection> = (0..400).map(|i| conn("203.0.113.9", i)).collect();
        let snap = snapshot_with(rows);
        let mut now = 1_700_000_000_000_000_000u64;
        let mut events = 0;
        for _ in 0..3 {
            events += svc.tick(Some(&snap), now);
            now += 1_000_000_000;
        }
        assert!(
            events > 0,
            "400 concurrent connections from one address is a flood"
        );
        let list = svc.store().list();
        let incident = list.alerts.first().expect("an incident");
        assert_eq!(incident.kind, AlertKindView::ConnFlood);
        assert_eq!(incident.source.as_deref(), Some("203.0.113.9"));
        assert_eq!(incident.phase, AlertPhaseView::Started);
        assert!(!incident.protected);
    }

    #[test]
    fn normal_connection_counts_stay_quiet() {
        let svc = service();
        let rows: Vec<Connection> = (0..20)
            .map(|i| conn(&format!("203.0.113.{}", i + 1), i))
            .collect();
        let snap = snapshot_with(rows);
        let mut now = 1_700_000_000_000_000_000u64;
        for _ in 0..5 {
            assert_eq!(svc.tick(Some(&snap), now), 0);
            now += 1_000_000_000;
        }
        assert!(svc.store().list().alerts.is_empty());
    }

    #[test]
    fn failed_logons_become_an_rdp_brute_force_incident() {
        let svc = service();
        let at = 1_700_000_000_000u64;
        for i in 0..15 {
            svc.logon_failure(LogonEvent {
                addr: "198.51.100.77".parse().unwrap(),
                at_unix_ms: at + i * 500,
            });
        }
        assert!(svc.tick(None, (at + 8_000) * 1_000_000) > 0);
        let list = svc.store().list();
        assert_eq!(list.alerts[0].kind, AlertKindView::RdpBruteForce);
        assert_eq!(list.alerts[0].source.as_deref(), Some("198.51.100.77"));
    }

    #[test]
    fn a_trusted_source_is_flagged_protected_but_still_reported() {
        let svc = service();
        svc.set_protected(protected_from(&["198.51.100.77".to_owned()]));
        let at = 1_700_000_000_000u64;
        for i in 0..15 {
            svc.logon_failure(LogonEvent {
                addr: "198.51.100.77".parse().unwrap(),
                at_unix_ms: at + i * 500,
            });
        }
        svc.tick(None, (at + 8_000) * 1_000_000);
        assert!(svc.store().list().alerts[0].protected);
    }

    #[test]
    fn captured_syn_floods_reach_the_detector() {
        let svc = service();
        let packets = testgen::syn_flood(
            "198.51.100.200".parse().unwrap(),
            1_700_000_000_000_000_000,
            10,
            5000,
        );
        let mut last_ns = 0;
        for chunk in packets.chunks(512) {
            svc.ingest(chunk);
            last_ns = chunk.last().map_or(last_ns, |p| p.timestamp_ns);
        }
        svc.tick(None, last_ns + 2_000_000_000);
        let kinds: Vec<AlertKindView> = svc.store().list().alerts.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&AlertKindView::SynFlood), "{kinds:?}");
    }

    #[test]
    fn the_store_merges_updates_keeps_the_peak_and_is_bounded() {
        let store = AlertStore::new(None);
        let base = |id: u64, phase, severity| AlertView {
            id,
            phase,
            kind: AlertKindView::UdpFlood,
            severity,
            source: None,
            summary_key: "udp_flood".into(),
            metrics: vec![],
            window_secs: 10,
            first_seen_unix_ms: id,
            last_seen_unix_ms: id,
            protected: false,
            peak_severity: severity,
        };
        store.record(base(1, AlertPhaseView::Started, AlertSeverity::Medium));
        store.record(base(1, AlertPhaseView::Escalated, AlertSeverity::Critical));
        store.record(base(1, AlertPhaseView::Ended, AlertSeverity::High));
        let list = store.list();
        assert_eq!(list.alerts.len(), 1);
        assert_eq!(list.alerts[0].phase, AlertPhaseView::Ended);
        assert_eq!(list.alerts[0].peak_severity, AlertSeverity::Critical);
        assert_eq!(list.alerts[0].severity, AlertSeverity::Critical);

        for id in 2..(KEEP_INCIDENTS as u64 + 50) {
            store.record(base(id, AlertPhaseView::Started, AlertSeverity::Low));
        }
        let list = store.list();
        assert_eq!(list.alerts.len(), KEEP_INCIDENTS);
        assert!(list.dropped > 0);
        assert!(list.alerts[0].id > list.alerts[1].id, "newest first");
        assert_eq!(store.clear_ended(), 0, "ongoing incidents stay");
    }

    #[test]
    fn incidents_survive_a_restart_as_ended_and_clearing_is_permanent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.jsonl");
        let started = AlertView {
            id: 7,
            phase: AlertPhaseView::Started,
            kind: AlertKindView::PortScan,
            severity: AlertSeverity::Low,
            source: Some("203.0.113.5".into()),
            summary_key: "port_scan_vertical".into(),
            metrics: vec![AlertMetric {
                key: "ports".into(),
                value: 120,
            }],
            window_secs: 60,
            first_seen_unix_ms: 1,
            last_seen_unix_ms: 2,
            protected: false,
            peak_severity: AlertSeverity::Low,
        };
        {
            let store = AlertStore::new(Some(path.clone()));
            store.record(started);
        }
        let store = AlertStore::new(Some(path.clone()));
        let list = store.list();
        assert_eq!(list.alerts.len(), 1);
        assert_eq!(
            list.alerts[0].phase,
            AlertPhaseView::Ended,
            "it cannot still be running"
        );
        assert_eq!(list.alerts[0].metrics[0].value, 120);
        assert_eq!(store.clear_ended(), 1);
        assert!(AlertStore::new(Some(path)).list().alerts.is_empty());
    }

    #[tokio::test]
    async fn alerts_reach_ipc_clients_through_the_topic_and_the_list() {
        use pw_ipc::memory::memory_pair;
        use pw_ipc::{serve, Client};
        use pw_netstat::fake::FakeNetStat;
        use pw_proto::{method, topic, ClientKind};

        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeNetStat::new());
        fake.set_connections(ConnectionTable {
            rows: (0..400).map(|i| conn("203.0.113.9", i)).collect(),
            processes: Default::default(),
        });
        let mut config = crate::EngineConfig::new("1", false);
        config.alerts_log = Some(dir.path().join("alerts.jsonl"));
        config.capture_dir = dir.path().join("c");
        config.poll_interval = std::time::Duration::from_millis(50);
        config.detect_interval = std::time::Duration::from_millis(50);
        let engine = Arc::new(crate::Engine::new(config, fake));
        let (listener, connector) = memory_pair();
        tokio::spawn(serve(listener, engine, std::future::pending()));
        let client = Client::connect(connector.connect().await.unwrap(), ClientKind::Pwctl, "t")
            .await
            .unwrap();
        let mut pushed = client.subscribe(topic::ALERTS).await.unwrap();
        let event: AlertView =
            tokio::time::timeout(std::time::Duration::from_secs(8), pushed.recv_as())
                .await
                .expect("an alert within 8 s")
                .unwrap();
        assert_eq!(event.kind, AlertKindView::ConnFlood);
        let list: AlertList = client.request(method::ALERTS_LIST, &()).await.unwrap();
        assert_eq!(list.alerts[0].id, event.id);
        let on_disk = std::fs::read_to_string(dir.path().join("alerts.jsonl")).unwrap();
        assert!(on_disk.contains("conn_flood"), "{on_disk}");
        // Clearing keeps the ongoing incident.
        let after: AlertList = client.request(method::ALERTS_CLEAR, &()).await.unwrap();
        assert_eq!(after.alerts.len(), list.alerts.len());
    }

    #[test]
    fn the_first_snapshot_does_not_count_every_connection_as_new() {
        let mut diff = ConnectionDiff::default();
        let snap = snapshot_with((0..5).map(|i| conn("203.0.113.9", i)).collect());
        let first = diff.counts(&snap);
        assert_eq!(first[0].1.new, 0);
        assert_eq!(first[0].1.concurrent, 5);
        let snap2 = snapshot_with((0..8).map(|i| conn("203.0.113.9", i)).collect());
        let second = diff.counts(&snap2);
        assert_eq!(second[0].1.new, 3);
    }
}
