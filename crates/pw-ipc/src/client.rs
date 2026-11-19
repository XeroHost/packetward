// SPDX-License-Identifier: GPL-3.0-or-later
//! Client side: handshake, request/response correlation and topic subscriptions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pw_proto::{
    method, ClientKind, Envelope, ErrorCode, ErrorPayload, HelloRequest, HelloResponse, Kind,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};

use crate::framing::{read_envelope, write_envelope, FrameError};

const OUTBOUND_QUEUE: usize = 64;
/// Events buffered per subscription. When the consumer lags, new events are dropped and counted.
const SUBSCRIPTION_QUEUE: usize = 64;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("the agent closed the connection")]
    Disconnected,
    #[error("the agent did not answer in time")]
    Timeout,
    #[error("the agent reported an error: {0:?}")]
    Remote(ErrorPayload),
    /// The agent speaks an older protocol major than this client.
    #[error("the agent is outdated (protocol {}.{}, agent {})", .0.protocol_major, .0.protocol_minor, .0.agent_version)]
    AgentOutdated(HelloResponse),
    /// The agent speaks a newer protocol major than this client.
    #[error("this app is outdated (agent protocol {}.{}, agent {})", .0.protocol_major, .0.protocol_minor, .0.agent_version)]
    ClientOutdated(HelloResponse),
    #[error("could not encode or decode a message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("framing error: {0}")]
    Frame(#[from] FrameError),
}

type Reply = Result<Value, ErrorPayload>;

#[derive(Default)]
struct Shared {
    pending: HashMap<u64, oneshot::Sender<Reply>>,
    subscriptions: HashMap<String, mpsc::Sender<Value>>,
    closed: bool,
}

struct Inner {
    out: mpsc::Sender<Envelope>,
    next_id: AtomicU64,
    shared: Mutex<Shared>,
    dropped_events: AtomicU64,
    closed_tx: watch::Sender<bool>,
    timeout: Duration,
}

impl Inner {
    fn shared(&self) -> MutexGuard<'_, Shared> {
        // The state stays consistent even if a holder panicked: every critical section is a single
        // map operation.
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A connected, handshaken client. Cheap to clone; all clones share one connection.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
    hello: Arc<HelloResponse>,
    // Dropped with the last clone: stops the reader task, which would otherwise keep the shared
    // state (and with it the writer task and the stream) alive forever.
    _reader: Arc<AbortOnDrop>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Events of one topic. The channel closes when the connection does.
pub struct Subscription {
    pub topic: String,
    events: mpsc::Receiver<Value>,
}

impl Subscription {
    /// Next raw payload, or `None` once the connection is gone.
    pub async fn recv(&mut self) -> Option<Value> {
        self.events.recv().await
    }

    /// Next payload decoded as `T`. A payload that does not decode is skipped with a warning.
    pub async fn recv_as<T: DeserializeOwned>(&mut self) -> Option<T> {
        loop {
            let value = self.events.recv().await?;
            match T::deserialize(&value) {
                Ok(typed) => return Some(typed),
                Err(err) => tracing::warn!(topic = %self.topic, %err, "dropping malformed event"),
            }
        }
    }
}

impl Client {
    /// Runs the version handshake over `stream`.
    pub async fn connect<S>(
        stream: S,
        kind: ClientKind,
        client_version: impl Into<String>,
    ) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with_timeout(stream, kind, client_version, DEFAULT_TIMEOUT).await
    }

    pub async fn connect_with_timeout<S>(
        stream: S,
        kind: ClientKind,
        client_version: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let (out, mut queue) = mpsc::channel::<Envelope>(OUTBOUND_QUEUE);
        let (closed_tx, _) = watch::channel(false);
        let inner = Arc::new(Inner {
            out,
            next_id: AtomicU64::new(1),
            shared: Mutex::new(Shared::default()),
            dropped_events: AtomicU64::new(0),
            closed_tx,
            timeout,
        });

        tokio::spawn(async move {
            while let Some(envelope) = queue.recv().await {
                if write_envelope(&mut writer, &envelope).await.is_err() {
                    break;
                }
            }
        });

        let reader_inner = Arc::clone(&inner);
        let reader_task = tokio::spawn(async move {
            loop {
                match read_envelope(&mut reader).await {
                    Ok(Some(envelope)) => dispatch(&reader_inner, envelope),
                    Ok(None) => break,
                    Err(err) if err.is_recoverable() => {
                        tracing::warn!(%err, "ignoring an unreadable frame from the agent");
                    }
                    Err(err) => {
                        tracing::debug!(%err, "ipc read failed");
                        break;
                    }
                }
            }
            let mut shared = reader_inner.shared();
            shared.closed = true;
            shared.pending.clear(); // dropping the senders wakes every waiter with Disconnected
            shared.subscriptions.clear(); // closes every Subscription
            drop(shared);
            reader_inner.closed_tx.send_replace(true);
        });

        let mut client = Client {
            inner,
            hello: Arc::new(HelloResponse {
                agent_version: String::new(),
                protocol_major: 0,
                protocol_minor: 0,
            }),
            _reader: Arc::new(AbortOnDrop(reader_task)),
        };
        let hello: HelloResponse = client
            .request(
                method::HELLO,
                &HelloRequest {
                    client: kind,
                    client_version: client_version.into(),
                    protocol_major: PROTOCOL_MAJOR,
                    protocol_minor: PROTOCOL_MINOR,
                },
            )
            .await?;
        if hello.protocol_major < PROTOCOL_MAJOR {
            return Err(ClientError::AgentOutdated(hello));
        }
        if hello.protocol_major > PROTOCOL_MAJOR {
            return Err(ClientError::ClientOutdated(hello));
        }
        client.hello = Arc::new(hello);
        Ok(client)
    }

    /// What the agent reported in the handshake.
    pub fn agent(&self) -> &HelloResponse {
        &self.hello
    }

    pub fn is_closed(&self) -> bool {
        *self.inner.closed_tx.borrow()
    }

    /// Completes when the connection is gone.
    pub async fn closed(&self) {
        let mut rx = self.inner.closed_tx.subscribe();
        // Err means the sender is gone, which only happens after close.
        let _ = rx.wait_for(|closed| *closed).await;
    }

    /// Events dropped because a subscriber was not keeping up.
    pub fn dropped_events(&self) -> u64 {
        self.inner.dropped_events.load(Ordering::Relaxed)
    }

    pub async fn request<Req, Res>(
        &self,
        method_name: &str,
        payload: &Req,
    ) -> Result<Res, ClientError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let envelope = Envelope::request(id, method_name, payload)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut shared = self.inner.shared();
            if shared.closed {
                return Err(ClientError::Disconnected);
            }
            shared.pending.insert(id, reply_tx);
        }
        if self.inner.out.send(envelope).await.is_err() {
            self.inner.shared().pending.remove(&id);
            return Err(ClientError::Disconnected);
        }
        let reply = match tokio::time::timeout(self.inner.timeout, reply_rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => return Err(ClientError::Disconnected),
            Err(_) => {
                self.inner.shared().pending.remove(&id);
                return Err(ClientError::Timeout);
            }
        };
        match reply {
            Ok(value) => Ok(Res::deserialize(value)?),
            Err(err) => Err(ClientError::Remote(err)),
        }
    }

    pub async fn subscribe(&self, topic: &str) -> Result<Subscription, ClientError> {
        let (tx, rx) = mpsc::channel(SUBSCRIPTION_QUEUE);
        // Register before asking so an event that races the reply is not lost.
        {
            let mut shared = self.inner.shared();
            if shared.closed {
                return Err(ClientError::Disconnected);
            }
            shared.subscriptions.insert(topic.to_owned(), tx);
        }
        let result: Result<SubscribeResponse, _> = self
            .request(
                method::SUBSCRIBE,
                &SubscribeRequest {
                    topic: topic.to_owned(),
                },
            )
            .await;
        if let Err(err) = result {
            self.inner.shared().subscriptions.remove(topic);
            return Err(err);
        }
        Ok(Subscription {
            topic: topic.to_owned(),
            events: rx,
        })
    }

    pub async fn unsubscribe(&self, topic: &str) -> Result<(), ClientError> {
        self.inner.shared().subscriptions.remove(topic);
        self.request::<_, Value>(
            method::UNSUBSCRIBE,
            &UnsubscribeRequest {
                topic: topic.to_owned(),
            },
        )
        .await?;
        Ok(())
    }
}

fn dispatch(inner: &Inner, envelope: Envelope) {
    match envelope.kind {
        Kind::Res => {
            let Some(id) = envelope.id else { return };
            if let Some(waiter) = inner.shared().pending.remove(&id) {
                let _ = waiter.send(Ok(envelope.payload));
            }
        }
        Kind::Err => {
            let error = envelope.payload_as::<ErrorPayload>().unwrap_or_else(|err| {
                ErrorPayload::new(
                    ErrorCode::Internal,
                    format!("unreadable error payload: {err}"),
                )
            });
            match envelope.id {
                Some(id) => {
                    if let Some(waiter) = inner.shared().pending.remove(&id) {
                        let _ = waiter.send(Err(error));
                    }
                }
                // Connection-level error (bad frame, version mismatch): nothing to correlate it to.
                None => tracing::warn!(?error, "agent reported a connection-level error"),
            }
        }
        Kind::Event => {
            let Some(topic) = envelope.topic else { return };
            let sender = inner.shared().subscriptions.get(&topic).cloned();
            if let Some(sender) = sender {
                if sender.try_send(envelope.payload).is_err() {
                    inner.dropped_events.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Kind::Req => {
            tracing::warn!("ignoring a request sent by the agent");
        }
    }
}
