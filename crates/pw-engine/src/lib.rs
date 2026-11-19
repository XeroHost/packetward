// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-engine — orchestrator: wires every crate together, owns tasks and state, exposes the API.
//!
//! M1 skeleton: answers `system.info` and publishes the `live.heartbeat` topic. The engine
//! implements [`pw_ipc::Handler`] itself, so the agent only has to hand it to `pw_ipc::serve`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pw_ipc::{EventReceiver, Handler};
use pw_proto::{
    method, topic, ErrorCode, ErrorPayload, Heartbeat, HelloResponse, SystemInfo, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Events buffered per heartbeat subscription before the producer waits for the consumer.
const HEARTBEAT_QUEUE: usize = 4;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub agent_version: String,
    /// True under the service control manager, false for `run --console`.
    pub service_mode: bool,
    pub heartbeat_interval: Duration,
}

impl EngineConfig {
    pub fn new(agent_version: impl Into<String>, service_mode: bool) -> Self {
        Self {
            agent_version: agent_version.into(),
            service_mode,
            heartbeat_interval: Duration::from_secs(1),
        }
    }
}

pub struct Engine {
    config: EngineConfig,
    started: Instant,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            started: Instant::now(),
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

fn hostname() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Handler for Engine {
    fn hello(&self) -> HelloResponse {
        HelloResponse {
            agent_version: self.config.agent_version.clone(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        }
    }

    async fn handle(&self, method_name: &str, _payload: Value) -> Result<Value, ErrorPayload> {
        match method_name {
            method::SYSTEM_INFO => serde_json::to_value(self.system_info())
                .map_err(|err| ErrorPayload::new(ErrorCode::Internal, err.to_string())),
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownMethod,
                format!("unknown method `{other}`"),
            )),
        }
    }

    async fn subscribe(&self, topic_name: &str) -> Result<EventReceiver, ErrorPayload> {
        match topic_name {
            topic::LIVE_HEARTBEAT => {
                let (tx, rx) = mpsc::channel(HEARTBEAT_QUEUE);
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
                            unix_ms: unix_ms(),
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
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownTopic,
                format!("unknown topic `{other}`"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pw_ipc::memory::{memory_pair, MemoryConnector};
    use pw_ipc::{serve, Client, ClientError};
    use pw_proto::ClientKind;

    use super::*;

    // The connector must outlive the test: when all connectors are gone the in-memory listener
    // reports an accept error and `serve` stops, taking its connections with it.
    async fn connect(config: EngineConfig) -> (Client, MemoryConnector) {
        let (listener, connector) = memory_pair();
        let engine = Arc::new(Engine::new(config));
        tokio::spawn(serve(listener, engine, std::future::pending()));
        let stream = connector.connect().await.unwrap();
        let client = Client::connect(stream, ClientKind::Pwctl, "test")
            .await
            .unwrap();
        (client, connector)
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
}
