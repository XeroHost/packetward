// SPDX-License-Identifier: GPL-3.0-or-later
//! End-to-end tests of client + server over the in-memory transport.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pw_proto::{
    method, ClientKind, Envelope, ErrorCode, ErrorPayload, HelloRequest, HelloResponse, Kind,
    MAX_FRAME_BYTES, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::framing::{read_envelope, read_frame, write_envelope, write_frame};
use crate::memory::{memory_pair, MemoryConnector};
use crate::{serve, Client, ClientError, ConnCtx, EventReceiver, Handler};

#[derive(Default)]
struct Probe {
    producer_stopped: AtomicBool,
    produced: AtomicU64,
}

struct TestHandler {
    major: u16,
    probe: Arc<Probe>,
}

impl Handler for TestHandler {
    fn hello(&self) -> HelloResponse {
        HelloResponse {
            agent_version: "test".into(),
            protocol_major: self.major,
            protocol_minor: PROTOCOL_MINOR,
        }
    }

    async fn handle(
        &self,
        _ctx: ConnCtx,
        method_name: &str,
        payload: Value,
    ) -> Result<Value, ErrorPayload> {
        match method_name {
            "echo" => Ok(payload),
            "slow" => {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(json!("slow"))
            }
            "hang" => std::future::pending().await,
            "fail" => Err(ErrorPayload::new(ErrorCode::Internal, "boom")),
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownMethod,
                format!("no such method {other}"),
            )),
        }
    }

    async fn subscribe(&self, _ctx: ConnCtx, topic: &str) -> Result<EventReceiver, ErrorPayload> {
        match topic {
            "ticks" => {
                let (tx, rx) = mpsc::channel(8);
                let probe = Arc::clone(&self.probe);
                tokio::spawn(async move {
                    for n in 1u64.. {
                        if tx.send(json!(n)).await.is_err() {
                            break;
                        }
                        probe.produced.store(n, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    probe.producer_stopped.store(true, Ordering::SeqCst);
                });
                Ok(rx)
            }
            "burst" => {
                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(async move {
                    for n in 0..500u64 {
                        if tx.send(json!(n)).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(rx)
            }
            other => Err(ErrorPayload::new(
                ErrorCode::UnknownTopic,
                format!("no such topic {other}"),
            )),
        }
    }
}

fn start(major: u16) -> (MemoryConnector, Arc<Probe>) {
    let (listener, connector) = memory_pair();
    let probe = Arc::new(Probe::default());
    let handler = Arc::new(TestHandler {
        major,
        probe: Arc::clone(&probe),
    });
    tokio::spawn(serve(listener, handler, std::future::pending()));
    (connector, probe)
}

async fn client(connector: &MemoryConnector) -> Client {
    let stream = connector.connect().await.unwrap();
    Client::connect(stream, ClientKind::Pwctl, "0.0.0")
        .await
        .unwrap()
}

fn hello_request(major: u16) -> Envelope {
    Envelope::request(
        1,
        method::HELLO,
        &HelloRequest {
            client: ClientKind::Pwctl,
            client_version: "0.0.0".into(),
            protocol_major: major,
            protocol_minor: 0,
        },
    )
    .unwrap()
}

#[tokio::test]
async fn handshake_reports_the_agent_versions() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    assert_eq!(client.agent().agent_version, "test");
    assert_eq!(client.agent().protocol_major, PROTOCOL_MAJOR);
}

struct KindHandler;

impl Handler for KindHandler {
    fn hello(&self) -> HelloResponse {
        HelloResponse {
            agent_version: "test".into(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
        }
    }

    async fn handle(
        &self,
        ctx: ConnCtx,
        _method_name: &str,
        _payload: Value,
    ) -> Result<Value, ErrorPayload> {
        Ok(json!(match ctx.client {
            ClientKind::Desktop => "desktop",
            ClientKind::Pwctl => "pwctl",
            ClientKind::Mcp => "mcp",
        }))
    }

    async fn subscribe(&self, ctx: ConnCtx, _topic: &str) -> Result<EventReceiver, ErrorPayload> {
        let (tx, rx) = mpsc::channel(1);
        let _ = tx.try_send(json!(match ctx.client {
            ClientKind::Desktop => "desktop",
            ClientKind::Pwctl => "pwctl",
            ClientKind::Mcp => "mcp",
        }));
        Ok(rx)
    }
}

#[tokio::test]
async fn the_hello_client_kind_reaches_the_handler() {
    let (listener, connector) = memory_pair();
    tokio::spawn(serve(
        listener,
        Arc::new(KindHandler),
        std::future::pending(),
    ));
    for (kind, expected) in [
        (ClientKind::Mcp, "mcp"),
        (ClientKind::Desktop, "desktop"),
        (ClientKind::Pwctl, "pwctl"),
    ] {
        let stream = connector.connect().await.unwrap();
        let client = Client::connect(stream, kind, "0.0.0").await.unwrap();
        let seen: Value = client.request("who", &()).await.unwrap();
        assert_eq!(seen, json!(expected));
        let mut events = client.subscribe("who").await.unwrap();
        let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("the kind event arrives");
        assert_eq!(event, Some(json!(expected)));
    }
}

#[tokio::test]
async fn a_newer_agent_makes_the_client_outdated() {
    let (connector, _) = start(PROTOCOL_MAJOR + 1);
    let stream = connector.connect().await.unwrap();
    let err = Client::connect(stream, ClientKind::Desktop, "0.0.0")
        .await
        .err()
        .unwrap();
    assert!(
        matches!(err, ClientError::ClientOutdated(h) if h.protocol_major == PROTOCOL_MAJOR + 1)
    );
}

#[tokio::test]
async fn an_older_agent_is_reported_as_outdated() {
    let (connector, _) = start(PROTOCOL_MAJOR - 1);
    let stream = connector.connect().await.unwrap();
    let err = Client::connect(stream, ClientKind::Desktop, "0.0.0")
        .await
        .err()
        .unwrap();
    assert!(matches!(err, ClientError::AgentOutdated(h) if h.protocol_major == PROTOCOL_MAJOR - 1));
}

#[tokio::test]
async fn the_server_closes_after_a_version_mismatch() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let mut stream = connector.connect().await.unwrap();
    write_envelope(&mut stream, &hello_request(PROTOCOL_MAJOR + 7))
        .await
        .unwrap();
    let hello = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(hello.kind, Kind::Res);
    let err = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(err.kind, Kind::Err);
    assert_eq!(
        err.payload_as::<ErrorPayload>().unwrap().code,
        ErrorCode::VersionMismatch
    );
    assert!(
        read_frame(&mut stream).await.unwrap().is_none(),
        "connection should be closed"
    );
}

#[tokio::test]
async fn requests_before_the_handshake_are_refused() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let mut stream = connector.connect().await.unwrap();
    write_envelope(
        &mut stream,
        &Envelope::request(9, "echo", &json!(1)).unwrap(),
    )
    .await
    .unwrap();
    let reply = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(reply.kind, Kind::Err);
    assert_eq!(reply.id, Some(9));
    assert_eq!(
        reply.payload_as::<ErrorPayload>().unwrap().code,
        ErrorCode::NotHandshaken
    );
}

#[tokio::test]
async fn requests_round_trip_and_errors_are_typed() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    let echoed: Value = client.request("echo", &json!({"a": 1})).await.unwrap();
    assert_eq!(echoed, json!({"a": 1}));

    let err = client.request::<_, Value>("nope", &()).await.unwrap_err();
    assert!(matches!(err, ClientError::Remote(e) if e.code == ErrorCode::UnknownMethod));
    let err = client.request::<_, Value>("fail", &()).await.unwrap_err();
    assert!(matches!(err, ClientError::Remote(e) if e.message == "boom"));
}

#[tokio::test]
async fn a_slow_request_does_not_block_a_fast_one() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    let slow_client = client.clone();
    let slow = tokio::spawn(async move { slow_client.request::<_, Value>("slow", &()).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let started = std::time::Instant::now();
    let _: Value = client.request("echo", &json!(1)).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(slow.await.unwrap().unwrap(), json!("slow"));
}

#[tokio::test]
async fn a_request_that_never_answers_times_out() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let stream = connector.connect().await.unwrap();
    let client = Client::connect_with_timeout(
        stream,
        ClientKind::Pwctl,
        "0.0.0",
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let err = client.request::<_, Value>("hang", &()).await.unwrap_err();
    assert!(matches!(err, ClientError::Timeout));
    // The connection is still usable afterwards.
    let _: Value = client.request("echo", &json!(1)).await.unwrap();
}

#[tokio::test]
async fn subscription_delivers_events_in_order_and_stops_on_unsubscribe() {
    let (connector, probe) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    let mut sub = client.subscribe("ticks").await.unwrap();
    for expected in 1u64..=3 {
        assert_eq!(sub.recv_as::<u64>().await, Some(expected));
    }
    client.unsubscribe("ticks").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        probe.producer_stopped.load(Ordering::SeqCst),
        "producer must stop after unsubscribe"
    );
}

#[tokio::test]
async fn subscribing_twice_is_a_no_op() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    let mut first = client.subscribe("ticks").await.unwrap();
    let _second = client.subscribe("ticks").await.unwrap();
    assert!(first.recv().await.is_some());
}

#[tokio::test]
async fn unknown_topics_are_rejected() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    let err = client.subscribe("nope").await.err().unwrap();
    assert!(matches!(err, ClientError::Remote(e) if e.code == ErrorCode::UnknownTopic));
}

#[tokio::test]
async fn dropping_the_connection_stops_producers_and_closes_the_client() {
    let (connector, probe) = start(PROTOCOL_MAJOR);
    let stream = connector.connect().await.unwrap();
    let client = Client::connect(stream, ClientKind::Pwctl, "0.0.0")
        .await
        .unwrap();
    let mut sub = client.subscribe("ticks").await.unwrap();
    assert!(sub.recv().await.is_some());
    // Closing the client side is seen by the server as end of stream.
    let closer = client.clone();
    drop(client);
    drop(closer);
    // All clones gone: the writer task ends, the stream closes, the server aborts the producer.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !probe.producer_stopped.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server did not clean up the subscription");
    // The subscription channel ends too.
    while sub.recv().await.is_some() {}
}

#[tokio::test]
async fn a_server_that_goes_away_fails_pending_requests_and_closes_subscriptions() {
    // A hand-rolled server so the test controls when the connection ends.
    let (mut server_side, client_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let hello = read_envelope(&mut server_side).await.unwrap().unwrap();
        let reply = Envelope::response(
            hello.id.unwrap(),
            &HelloResponse {
                agent_version: "fake".into(),
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: 0,
            },
        )
        .unwrap();
        write_envelope(&mut server_side, &reply).await.unwrap();
        // Read the next request and then vanish without answering.
        let _ = read_envelope(&mut server_side).await;
    });
    let client = Client::connect(client_side, ClientKind::Pwctl, "0.0.0")
        .await
        .unwrap();
    let err = client.request::<_, Value>("echo", &()).await.unwrap_err();
    assert!(matches!(err, ClientError::Disconnected));
    server.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), client.closed())
        .await
        .unwrap();
    assert!(client.is_closed());
    let err = client.request::<_, Value>("echo", &()).await.unwrap_err();
    assert!(matches!(err, ClientError::Disconnected));
}

#[tokio::test]
async fn a_lagging_subscriber_loses_events_instead_of_growing_memory() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let client = client(&connector).await;
    let mut sub = client.subscribe("burst").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await; // never read meanwhile
    assert!(client.dropped_events() > 0, "overflow must be counted");
    // What was buffered is still readable and bounded.
    let mut received = 0;
    while tokio::time::timeout(Duration::from_millis(50), sub.recv())
        .await
        .is_ok()
    {
        received += 1;
        if received > 100 {
            break;
        }
    }
    assert!(
        received <= 64 + 8,
        "buffer must stay bounded, got {received}"
    );
}

#[tokio::test]
async fn bad_json_gets_an_error_and_the_connection_survives() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let mut stream = connector.connect().await.unwrap();
    write_envelope(&mut stream, &hello_request(PROTOCOL_MAJOR))
        .await
        .unwrap();
    let _ = read_envelope(&mut stream).await.unwrap().unwrap();

    write_frame(&mut stream, b"{ this is not json")
        .await
        .unwrap();
    let err = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(
        err.payload_as::<ErrorPayload>().unwrap().code,
        ErrorCode::BadRequest
    );

    write_envelope(
        &mut stream,
        &Envelope::request(2, "echo", &json!(5)).unwrap(),
    )
    .await
    .unwrap();
    let ok = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(ok.kind, Kind::Res);
    assert_eq!(ok.payload, json!(5));
}

#[tokio::test]
async fn a_malformed_envelope_gets_bad_request() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let mut stream = connector.connect().await.unwrap();
    write_envelope(&mut stream, &hello_request(PROTOCOL_MAJOR))
        .await
        .unwrap();
    let _ = read_envelope(&mut stream).await.unwrap().unwrap();

    let mut no_method = Envelope::request(4, "echo", &()).unwrap();
    no_method.method = None;
    write_envelope(&mut stream, &no_method).await.unwrap();
    let err = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(
        err.payload_as::<ErrorPayload>().unwrap().code,
        ErrorCode::BadRequest
    );
}

#[tokio::test]
async fn an_oversized_frame_is_refused_and_the_connection_closed() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let mut stream = connector.connect().await.unwrap();
    write_envelope(&mut stream, &hello_request(PROTOCOL_MAJOR))
        .await
        .unwrap();
    let _ = read_envelope(&mut stream).await.unwrap().unwrap();

    stream
        .write_all(&(MAX_FRAME_BYTES + 1).to_le_bytes())
        .await
        .unwrap();
    let err = read_envelope(&mut stream).await.unwrap().unwrap();
    assert_eq!(
        err.payload_as::<ErrorPayload>().unwrap().code,
        ErrorCode::FrameTooLarge
    );
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert!(
        rest.is_empty(),
        "nothing more after the error, and the stream ends"
    );
}

#[tokio::test]
async fn many_clients_are_served_independently() {
    let (connector, _) = start(PROTOCOL_MAJOR);
    let mut joins = Vec::new();
    for i in 0..20u64 {
        let connector = connector.clone();
        joins.push(tokio::spawn(async move {
            let client = client(&connector).await;
            let echoed: u64 = client.request("echo", &i).await.unwrap();
            assert_eq!(echoed, i);
        }));
    }
    for join in joins {
        join.await.unwrap();
    }
}

#[tokio::test]
async fn serve_reports_a_listener_failure_but_not_a_requested_shutdown() {
    // Listener dies on its own (every connector dropped): the caller must hear about it.
    let (listener, connector) = memory_pair();
    let handler = Arc::new(TestHandler {
        major: PROTOCOL_MAJOR,
        probe: Arc::new(Probe::default()),
    });
    drop(connector);
    let result = serve(listener, Arc::clone(&handler), std::future::pending()).await;
    assert!(
        result.is_err(),
        "an accept failure is an error, not a clean stop"
    );

    // A requested shutdown is the one clean way out.
    let (listener, _connector) = memory_pair();
    let result = serve(listener, handler, std::future::ready(())).await;
    assert!(result.is_ok());
}
