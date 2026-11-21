// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Server side: accept connections, run the version handshake, dispatch requests to a [`Handler`]
//! and forward topic subscriptions as events.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use pw_proto::{
    method, Envelope, ErrorCode, ErrorPayload, HelloRequest, HelloResponse, Kind, SubscribeRequest,
    SubscribeResponse, UnsubscribeRequest, PROTOCOL_MAJOR,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use crate::framing::{read_envelope, write_envelope, FrameError};

/// Events queued towards one connection before producers feel back-pressure.
const OUTBOUND_QUEUE: usize = 64;
/// How long a closing connection may spend flushing already queued frames.
const FLUSH_GRACE: Duration = Duration::from_secs(1);

/// Stream of event payloads for one subscription. Dropping it tells the producer to stop.
pub type EventReceiver = mpsc::Receiver<Value>;

/// What the connection declared in its `session.hello`: the agent applies per-kind policy (an MCP
/// connection only reaches the MCP catalog, ARCHITECTURE 6.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnCtx {
    pub client: pw_proto::ClientKind,
}

/// The application behind the pipe. Implemented by the agent on top of `pw-engine`.
pub trait Handler: Send + Sync + 'static {
    /// Versions reported in the handshake.
    fn hello(&self) -> HelloResponse;

    /// Handles one request. Must return [`ErrorCode::UnknownMethod`] for methods it does not know.
    fn handle(
        &self,
        ctx: ConnCtx,
        method: &str,
        payload: Value,
    ) -> impl Future<Output = Result<Value, ErrorPayload>> + Send;

    /// Opens a subscription. Must return [`ErrorCode::UnknownTopic`] for unknown topics.
    fn subscribe(
        &self,
        ctx: ConnCtx,
        topic: &str,
    ) -> impl Future<Output = Result<EventReceiver, ErrorPayload>> + Send;
}

/// Source of incoming connections (named pipe in production, in-memory in tests).
pub trait Listener: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept(&mut self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Accepts connections until `shutdown` completes; every connection runs as its own task and is
/// dropped when the server stops.
///
/// Returns `Ok` only for a requested shutdown. If the listener itself fails, the error is returned
/// so the caller can exit non-zero (a service that stops "cleanly" is not restarted by Windows).
pub async fn serve<L, H, S>(mut listener: L, handler: Arc<H>, shutdown: S) -> io::Result<()>
where
    L: Listener,
    H: Handler,
    S: Future<Output = ()> + Send,
{
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    let outcome = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(stream) => {
                    connections.spawn(serve_connection(stream, Arc::clone(&handler)));
                }
                Err(err) => {
                    tracing::error!(%err, "accept failed; stopping the IPC server");
                    break Err(err);
                }
            },
            // Reap finished connections so the set does not grow forever.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };
    connections.abort_all();
    outcome
}

fn error_envelope(
    id: Option<u64>,
    code: ErrorCode,
    message: impl Into<String>,
) -> Option<Envelope> {
    Envelope::error(id, &ErrorPayload::new(code, message)).ok()
}

/// Runs one connection to completion.
pub async fn serve_connection<S, H>(stream: S, handler: Arc<H>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: Handler,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (out, mut queue) = mpsc::channel::<Envelope>(OUTBOUND_QUEUE);

    let writer_task = tokio::spawn(async move {
        while let Some(envelope) = queue.recv().await {
            if let Err(err) = write_envelope(&mut writer, &envelope).await {
                tracing::debug!(%err, "ipc write failed; closing connection");
                break;
            }
        }
    });

    let mut subscriptions: HashMap<String, JoinHandle<()>> = HashMap::new();
    let mut handshaken = false;
    // Captured from the hello; only requests that passed the handshake reach the handler.
    let mut client_kind = None;

    loop {
        let envelope = match read_envelope(&mut reader).await {
            Ok(Some(envelope)) => envelope,
            Ok(None) => break,
            Err(err) if err.is_recoverable() => {
                if let Some(reply) = error_envelope(None, ErrorCode::BadRequest, err.to_string()) {
                    let _ = out.send(reply).await;
                }
                continue;
            }
            Err(FrameError::TooLarge(len)) => {
                if let Some(reply) = error_envelope(
                    None,
                    ErrorCode::FrameTooLarge,
                    format!("frame of {len} bytes is over the limit"),
                ) {
                    let _ = out.send(reply).await;
                }
                break; // the stream cannot be re-aligned
            }
            Err(err) => {
                tracing::debug!(%err, "ipc read failed; closing connection");
                break;
            }
        };

        if let Err(shape) = envelope.check_shape() {
            if let Some(reply) =
                error_envelope(envelope.id, ErrorCode::BadRequest, shape.to_string())
            {
                let _ = out.send(reply).await;
            }
            continue;
        }
        let (Kind::Req, Some(id), Some(method_name)) =
            (envelope.kind, envelope.id, envelope.method.clone())
        else {
            if let Some(reply) = error_envelope(
                envelope.id,
                ErrorCode::BadRequest,
                "clients may only send requests",
            ) {
                let _ = out.send(reply).await;
            }
            continue;
        };

        if !handshaken && method_name != method::HELLO {
            if let Some(reply) = error_envelope(
                Some(id),
                ErrorCode::NotHandshaken,
                "send session.hello before any other request",
            ) {
                let _ = out.send(reply).await;
            }
            continue;
        }

        match method_name.as_str() {
            method::HELLO => {
                let request: HelloRequest = match envelope.payload_as() {
                    Ok(request) => request,
                    Err(err) => {
                        if let Some(reply) =
                            error_envelope(Some(id), ErrorCode::BadRequest, err.to_string())
                        {
                            let _ = out.send(reply).await;
                        }
                        continue;
                    }
                };
                let ours = handler.hello();
                if let Ok(reply) = Envelope::response(id, &ours) {
                    let _ = out.send(reply).await;
                }
                if request.protocol_major != PROTOCOL_MAJOR || ours.protocol_major != PROTOCOL_MAJOR
                {
                    if let Some(reply) = error_envelope(
                        None,
                        ErrorCode::VersionMismatch,
                        format!(
                            "client speaks protocol {}, agent speaks {}",
                            request.protocol_major, ours.protocol_major
                        ),
                    ) {
                        let _ = out.send(reply).await;
                    }
                    break;
                }
                handshaken = true;
                client_kind = Some(request.client);
            }
            method::SUBSCRIBE => {
                let request: SubscribeRequest = match envelope.payload_as() {
                    Ok(request) => request,
                    Err(err) => {
                        if let Some(reply) =
                            error_envelope(Some(id), ErrorCode::BadRequest, err.to_string())
                        {
                            let _ = out.send(reply).await;
                        }
                        continue;
                    }
                };
                let ctx = ConnCtx {
                    // Only a handshaken connection gets here, so the kind is always known; the
                    // fallback is the least privileged interactive client.
                    client: client_kind.unwrap_or(pw_proto::ClientKind::Pwctl),
                };
                if subscriptions.contains_key(&request.topic) {
                    if let Ok(reply) = Envelope::response(
                        id,
                        &SubscribeResponse {
                            topic: request.topic,
                        },
                    ) {
                        let _ = out.send(reply).await;
                    }
                    continue;
                }
                match handler.subscribe(ctx, &request.topic).await {
                    Ok(mut events) => {
                        let topic = request.topic.clone();
                        // Reply first so the client sees the response before the first event.
                        if let Ok(reply) = Envelope::response(
                            id,
                            &SubscribeResponse {
                                topic: topic.clone(),
                            },
                        ) {
                            let _ = out.send(reply).await;
                        }
                        let forward_out = out.clone();
                        let forward_topic = topic.clone();
                        let task = tokio::spawn(async move {
                            while let Some(payload) = events.recv().await {
                                let Ok(event) = Envelope::event(&forward_topic, &payload) else {
                                    continue;
                                };
                                if forward_out.send(event).await.is_err() {
                                    break;
                                }
                            }
                        });
                        subscriptions.insert(topic, task);
                    }
                    Err(err) => {
                        if let Ok(reply) = Envelope::error(Some(id), &err) {
                            let _ = out.send(reply).await;
                        }
                    }
                }
            }
            method::UNSUBSCRIBE => {
                let request: UnsubscribeRequest = match envelope.payload_as() {
                    Ok(request) => request,
                    Err(err) => {
                        if let Some(reply) =
                            error_envelope(Some(id), ErrorCode::BadRequest, err.to_string())
                        {
                            let _ = out.send(reply).await;
                        }
                        continue;
                    }
                };
                if let Some(task) = subscriptions.remove(&request.topic) {
                    task.abort();
                }
                if let Ok(reply) = Envelope::response(id, &()) {
                    let _ = out.send(reply).await;
                }
            }
            _ => {
                // Handled off the read loop so a slow method does not stall the connection.
                let handler = Arc::clone(&handler);
                let out = out.clone();
                let payload = envelope.payload;
                let ctx = ConnCtx {
                    client: client_kind.unwrap_or(pw_proto::ClientKind::Pwctl),
                };
                tokio::spawn(async move {
                    let reply = match handler.handle(ctx, &method_name, payload).await {
                        Ok(value) => Envelope::response(id, &value),
                        Err(err) => Envelope::error(Some(id), &err),
                    };
                    if let Ok(reply) = reply {
                        let _ = out.send(reply).await;
                    }
                });
            }
        }
    }

    for (_, task) in subscriptions.drain() {
        task.abort();
    }
    drop(out);
    // Let already queued replies (e.g. the version-mismatch error) go out before closing; requests
    // still running keep the queue open, so do not wait for them forever.
    let mut writer_task = writer_task;
    if tokio::time::timeout(FLUSH_GRACE, &mut writer_task)
        .await
        .is_err()
    {
        tracing::debug!("ipc writer did not drain in time");
        writer_task.abort();
    }
}
