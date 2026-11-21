// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Listener, connection handling (HTTP/1.1, optional TLS), idle timeouts and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tower::ServiceExt;

use crate::app::{router, AppState, PeerAddr};
use crate::config::{Config, ConfigError};
use crate::io::IdleIo;
use crate::limits::Stats;

#[cfg(feature = "tls")]
mod tls;

/// Errors starting the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Invalid configuration.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Could not bind the listen address.
    #[error("cannot bind {addr}: {source}")]
    Bind {
        /// Address that failed.
        addr: SocketAddr,
        /// Underlying error.
        source: std::io::Error,
    },
    /// TLS certificate or key problem.
    #[error("TLS setup failed: {0}")]
    Tls(String),
    /// TLS is configured but this binary was built without the `tls` feature.
    #[error("[tls] is configured but this binary was built without the `tls` cargo feature")]
    TlsUnavailable,
}

/// A running server. Drop it or call [`RunningServer::shutdown`] to stop accepting; use
/// [`RunningServer::wait`] to wait for connections to drain.
pub struct RunningServer {
    local_addr: SocketAddr,
    stats: Arc<Stats>,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl RunningServer {
    /// The bound address (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shared counters.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// Ask the server to stop: no new connections, idle keep-alive connections close, in-flight transfers
    /// get `shutdown_grace_secs` to finish.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Wait until the accept loop and all connections have finished.
    pub async fn wait(self) {
        let _ = self.task.await;
    }
}

struct ConnCtx {
    app: AppState,
    router: axum::Router,
    idle: Duration,
    header_timeout: Duration,
    #[cfg(feature = "tls")]
    tls: Option<tokio_rustls::TlsAcceptor>,
}

/// Validate `config`, bind the listener and start serving in the background.
pub async fn start(config: Config) -> Result<RunningServer, ServerError> {
    config.validate()?;
    #[cfg(not(feature = "tls"))]
    if config.tls.enabled() {
        return Err(ServerError::TlsUnavailable);
    }
    #[cfg(feature = "tls")]
    let tls = match (&config.tls.cert_file, &config.tls.key_file) {
        (Some(cert), Some(key)) => Some(tls::acceptor(cert, key)?),
        _ => None,
    };
    let listen = config.server.listen;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|source| ServerError::Bind {
            addr: listen,
            source,
        })?;
    let local_addr = listener.local_addr().map_err(|source| ServerError::Bind {
        addr: listen,
        source,
    })?;

    let app = AppState::new(config)?;
    let stats = Arc::clone(app.stats());
    let cfg = app.config();
    let ctx = Arc::new(ConnCtx {
        router: router(app.clone()),
        idle: cfg.idle_timeout(),
        header_timeout: cfg.header_read_timeout(),
        #[cfg(feature = "tls")]
        tls,
        app,
    });
    let secure = cfg!(feature = "tls") && ctx.app.config().tls.enabled();
    tracing::info!(
        addr = %local_addr,
        node = %ctx.app.config().node.id,
        tls = secure,
        version = env!("CARGO_PKG_VERSION"),
        "pw-speed-server listening"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(accept_loop(listener, ctx, shutdown_rx));
    Ok(RunningServer {
        local_addr,
        stats,
        shutdown_tx,
        task,
    })
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            // Sender gone: treat as shutdown.
            return;
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<ConnCtx>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(ctx.app.config().server.max_connections));
    let grace = Duration::from_secs(ctx.app.config().server.shutdown_grace_secs);
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        // Bound the number of open connections: wait for a free slot before accepting more.
        let slot = tokio::select! {
            s = Arc::clone(&slots).acquire_owned() => match s {
                Ok(s) => s,
                Err(_) => break,
            },
            () = wait_shutdown(&mut shutdown_rx) => break,
        };
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = wait_shutdown(&mut shutdown_rx) => break,
        };
        while tasks.try_join_next().is_some() {}
        let ctx = Arc::clone(&ctx);
        let rx = shutdown_rx.clone();
        tasks.spawn(async move {
            handle_connection(stream, peer, ctx, rx).await;
            drop(slot);
        });
    }
    drop(listener);
    tracing::info!(
        open_connections = tasks.len(),
        "shutting down, draining connections"
    );
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(grace, drain).await.is_err() {
        tracing::warn!("grace period over, closing remaining connections");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ConnCtx>,
    shutdown_rx: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    // Per-IP connection cap, except for trusted reverse proxies (all their clients share one address).
    let _conn_guard = if ctx.app.proxy().is_trusted_proxy(peer.ip()) {
        None
    } else {
        match ctx.app.limiter().open_connection(peer.ip(), Instant::now()) {
            Some(g) => Some(g),
            None => {
                tracing::debug!(client = %crate::payload::client_label(peer.ip(), ctx.app.config().logging.log_full_ips), "too many connections, dropping");
                return;
            }
        }
    };

    #[cfg(feature = "tls")]
    if let Some(acceptor) = &ctx.tls {
        match tokio::time::timeout(ctx.header_timeout, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => serve_io(tls_stream, peer, &ctx, shutdown_rx).await,
            Ok(Err(e)) => tracing::debug!(error = %e, "TLS handshake failed"),
            Err(_) => tracing::debug!("TLS handshake timed out"),
        }
        return;
    }
    serve_io(stream, peer, &ctx, shutdown_rx).await;
}

async fn serve_io<IO>(
    io: IO,
    peer: SocketAddr,
    ctx: &ConnCtx,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(IdleIo::new(io, ctx.idle));
    let router = ctx.router.clone();
    let service = service_fn(move |req: hyper::Request<Incoming>| {
        let router = router.clone();
        async move {
            let mut req = req.map(axum::body::Body::new);
            req.extensions_mut().insert(PeerAddr(peer));
            router.oneshot(req).await
        }
    });
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(ctx.header_timeout)
        .keep_alive(true)
        .serve_connection(io, service);
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => log_conn_result(r),
        () = wait_shutdown(&mut shutdown_rx) => {
            conn.as_mut().graceful_shutdown();
            log_conn_result(conn.await);
        }
    }
}

fn log_conn_result(r: Result<(), hyper::Error>) {
    if let Err(e) = r {
        // Client resets, idle timeouts and aborted downloads are routine on a speed-test server.
        tracing::debug!(error = %e, "connection closed with error");
    }
}
