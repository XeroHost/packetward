// SPDX-License-Identifier: GPL-3.0-or-later
//! A scripted [`SpeedTransport`] for tests: no sockets, a constant byte rate on the (tokio) clock, recorded calls.
//! With `tokio::time::pause` a 12-second speed test runs in microseconds and is exactly reproducible.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::error::TransportError;
use super::server::{ServerEndpoint, ServerInfo};
use super::transport::{ByteMeter, DownloadRequest, SpeedTransport, UploadRequest};

/// Which operation a recorded call was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// `/ping`.
    Ping,
    /// `/info`.
    Info,
    /// `/download`.
    Download,
    /// `/upload`.
    Upload,
}

/// One call the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeCall {
    /// Operation.
    pub kind: CallKind,
    /// `host:port` of the server.
    pub server: String,
    /// Requested bytes (transfers only).
    pub bytes: u64,
    /// The `?test=` id (transfers only).
    pub test_id: String,
}

struct State {
    /// Per server: scripted ping results, consumed in order; the last one repeats. No entry = dead server.
    pings: HashMap<String, (Vec<Result<Duration, TransportError>>, usize)>,
    infos: HashMap<String, Result<ServerInfo, TransportError>>,
    rate_bytes_per_sec: u64,
    step: Duration,
    transfer_error: Option<TransportError>,
    calls: Vec<FakeCall>,
}

/// The fake. Cloning shares the state.
#[derive(Clone)]
pub struct FakeTransport {
    state: Arc<Mutex<State>>,
    moved: Arc<AtomicU64>,
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTransport {
    /// No servers answer, transfers run at 1 MB/s in 10 ms steps.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                pings: HashMap::new(),
                infos: HashMap::new(),
                rate_bytes_per_sec: 1_000_000,
                step: Duration::from_millis(10),
                transfer_error: None,
                calls: Vec::new(),
            })),
            moved: Arc::new(AtomicU64::new(0)),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Make `authority` (`host:port`) answer every ping after `rtt`.
    pub fn set_latency(&self, authority: &str, rtt: Duration) {
        self.set_ping_script(authority, vec![Ok(rtt)]);
    }

    /// Scripted ping results for `authority`: consumed in order, the last repeats.
    pub fn set_ping_script(&self, authority: &str, script: Vec<Result<Duration, TransportError>>) {
        self.state().pings.insert(authority.to_owned(), (script, 0));
    }

    /// What `/info` of `authority` answers (no entry = timeout).
    pub fn set_info(&self, authority: &str, info: Result<ServerInfo, TransportError>) {
        self.state().infos.insert(authority.to_owned(), info);
    }

    /// Payload rate of every transfer, in bytes per second. `0` makes transfers hang (to test stalls).
    pub fn set_rate(&self, bytes_per_sec: u64) {
        self.state().rate_bytes_per_sec = bytes_per_sec;
    }

    /// Make every download and upload fail immediately with `error` (`None` clears it).
    pub fn fail_transfers_with(&self, error: Option<TransportError>) {
        self.state().transfer_error = error;
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<FakeCall> {
        self.state().calls.clone()
    }

    /// Calls of one kind.
    pub fn calls_of(&self, kind: CallKind) -> Vec<FakeCall> {
        self.calls()
            .into_iter()
            .filter(|c| c.kind == kind)
            .collect()
    }

    /// Bytes the fake has "moved" in total, independent of the run's own meter. A cancelled run must stop this
    /// from growing.
    pub fn bytes_moved(&self) -> u64 {
        self.moved.load(Ordering::SeqCst)
    }

    fn record(&self, kind: CallKind, server: &ServerEndpoint, bytes: u64, test_id: &str) {
        self.state().calls.push(FakeCall {
            kind,
            server: server.authority(),
            bytes,
            test_id: test_id.to_owned(),
        });
    }

    async fn transfer(
        &self,
        kind: CallKind,
        server: &ServerEndpoint,
        bytes: u64,
        test_id: &str,
        meter: &ByteMeter,
    ) -> Result<u64, TransportError> {
        self.record(kind, server, bytes, test_id);
        let (rate, step, error) = {
            let state = self.state();
            (
                state.rate_bytes_per_sec,
                state.step,
                state.transfer_error.clone(),
            )
        };
        if let Some(error) = error {
            tokio::task::yield_now().await;
            return Err(error);
        }
        if rate == 0 {
            std::future::pending::<()>().await;
        }
        let per_step = ((u128::from(rate) * step.as_millis()) / 1000).max(1);
        let per_step = u64::try_from(per_step).unwrap_or(u64::MAX);
        let mut left = bytes;
        while left > 0 {
            tokio::time::sleep(step).await;
            let n = left.min(per_step);
            meter.add(n);
            self.moved.fetch_add(n, Ordering::SeqCst);
            left -= n;
        }
        Ok(bytes)
    }
}

impl SpeedTransport for FakeTransport {
    async fn ping(
        &self,
        server: &ServerEndpoint,
        _timeout: Duration,
    ) -> Result<Duration, TransportError> {
        self.record(CallKind::Ping, server, 0, "");
        let mut state = self.state();
        let Some((script, next)) = state.pings.get_mut(&server.authority()) else {
            return Err(TransportError::Timeout);
        };
        let index = (*next).min(script.len().saturating_sub(1));
        *next += 1;
        script
            .get(index)
            .cloned()
            .unwrap_or(Err(TransportError::Timeout))
    }

    async fn info(
        &self,
        server: &ServerEndpoint,
        _timeout: Duration,
    ) -> Result<ServerInfo, TransportError> {
        self.record(CallKind::Info, server, 0, "");
        self.state()
            .infos
            .get(&server.authority())
            .cloned()
            .unwrap_or(Err(TransportError::Timeout))
    }

    async fn download(
        &self,
        server: &ServerEndpoint,
        request: &DownloadRequest<'_>,
        meter: &ByteMeter,
    ) -> Result<u64, TransportError> {
        self.transfer(
            CallKind::Download,
            server,
            request.bytes,
            request.test_id,
            meter,
        )
        .await
    }

    async fn upload(
        &self,
        server: &ServerEndpoint,
        request: &UploadRequest<'_>,
        meter: &ByteMeter,
    ) -> Result<u64, TransportError> {
        self.transfer(
            CallKind::Upload,
            server,
            request.bytes,
            request.test_id,
            meter,
        )
        .await
    }
}
