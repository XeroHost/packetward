// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-engine — orchestrator: wires every crate together, owns tasks and state, exposes the API.
//!
//! Answers `system.info` and `netstat.connections`, and publishes the `live.heartbeat` and
//! `live.stats` topics. The engine implements [`pw_ipc::Handler`] itself, so the agent only has to
//! hand it to `pw_ipc::serve`.

mod connections;
mod poller;

use std::sync::Arc;
use std::time::Duration;

use pw_ipc::{EventReceiver, Handler};
use pw_netstat::NetStat;
use pw_proto::{
    method, topic, ConnectionsRequest, ErrorCode, ErrorPayload, Heartbeat, HelloResponse,
    SystemInfo, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use serde_json::Value;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

pub use poller::{Poller, Snapshot};

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
}

impl EngineConfig {
    pub fn new(agent_version: impl Into<String>, service_mode: bool) -> Self {
        Self {
            agent_version: agent_version.into(),
            service_mode,
            heartbeat_interval: Duration::from_secs(1),
            poll_interval: Duration::from_secs(1),
            rdp_refresh_every: 5,
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
    _poller: AbortOnDrop,
}

impl Engine {
    /// Starts the engine and its network poller. Must be called inside a tokio runtime.
    pub fn new(config: EngineConfig, netstat: Arc<dyn NetStat>) -> Self {
        let (publish, latest) = watch::channel(None);
        let task = tokio::spawn(poll_loop(
            netstat,
            publish,
            config.poll_interval,
            config.rdp_refresh_every,
        ));
        Self {
            config,
            started: Instant::now(),
            latest,
            _poller: AbortOnDrop(task),
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

/// Reads the network on a blocking thread every `period` and publishes the result.
async fn poll_loop(
    netstat: Arc<dyn NetStat>,
    publish: watch::Sender<Option<Arc<Snapshot>>>,
    period: Duration,
    rdp_every: u32,
) {
    let mut poller = Some(Poller::new(Arc::clone(&netstat), rdp_every));
    let mut ticker = tokio::time::interval(period);
    // A slow poll delays the next one instead of queueing a burst of catch-up polls.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        // If a previous poll panicked the poller was lost with it; start over with a fresh one.
        let mut current = poller
            .take()
            .unwrap_or_else(|| Poller::new(Arc::clone(&netstat), rdp_every));
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
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownTopic,
                format!("unknown topic `{other}`"),
            )),
        }
    }
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
}
