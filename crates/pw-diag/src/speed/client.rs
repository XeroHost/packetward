// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! [`SpeedClient`]: the entry point that ties transport, budget ledger and the individual tests together.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{CancelToken, Sink};

use super::error::SpeedError;
use super::latency::LatencyOptions;
use super::ledger::UsageLedger;
use super::picker::PickOptions;
use super::result::{ServerSummary, SpeedPhase, SpeedProgress, SpeedResult};
use super::server::{ServerEndpoint, ServerInfo};
use super::throughput::ThroughputOptions;
use super::transport::SpeedTransport;

/// How long `/info` may take.
const INFO_TIMEOUT: Duration = Duration::from_secs(3);

/// The speed-test client. Cheap to clone; clones share the transport and the budget ledger.
pub struct SpeedClient<T: SpeedTransport> {
    pub(crate) transport: Arc<T>,
    pub(crate) ledger: Arc<UsageLedger>,
}

impl<T: SpeedTransport> Clone for SpeedClient<T> {
    fn clone(&self) -> Self {
        Self {
            transport: Arc::clone(&self.transport),
            ledger: Arc::clone(&self.ledger),
        }
    }
}

/// What [`SpeedClient::run`] measures. `None` skips a step.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Server selection.
    pub pick: PickOptions,
    /// Latency and jitter.
    pub latency: Option<LatencyOptions>,
    /// Multi-stream download.
    pub download: Option<ThroughputOptions>,
    /// Multi-stream upload.
    pub upload: Option<ThroughputOptions>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            pick: PickOptions::default(),
            latency: Some(LatencyOptions::default()),
            download: Some(ThroughputOptions::default()),
            upload: Some(ThroughputOptions::default()),
        }
    }
}

impl<T: SpeedTransport> SpeedClient<T> {
    /// A client with its own (empty) budget ledger.
    pub fn new(transport: T) -> Self {
        Self::with_ledger(Arc::new(transport), Arc::new(UsageLedger::new()))
    }

    /// A client sharing `transport` and a ledger (so budget accounting survives across clients).
    pub fn with_ledger(transport: Arc<T>, ledger: Arc<UsageLedger>) -> Self {
        Self { transport, ledger }
    }

    /// The budget ledger.
    pub fn ledger(&self) -> &Arc<UsageLedger> {
        &self.ledger
    }

    /// `/info` of `server`: limits and this machine's public IP as the server sees it.
    pub async fn server_info(
        &self,
        server: &ServerEndpoint,
        cancel: &CancelToken,
    ) -> Result<ServerInfo, SpeedError> {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(SpeedError::Cancelled),
            result = self.transport.info(server, INFO_TIMEOUT) => result.map_err(SpeedError::from),
        }
    }

    /// The whole test: pick the lowest-latency candidate, ask it for `/info` (limits and the source IP), then run
    /// the requested steps against it. An empty candidate list, or one where nothing answers, is
    /// [`SpeedError::NoServer`]. A failing `/info` is not fatal: the run goes on without published limits and the
    /// result carries no source IP.
    pub async fn run<S: Sink<SpeedProgress>>(
        &self,
        candidates: &[ServerEndpoint],
        options: &RunOptions,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<SpeedResult, SpeedError> {
        let started_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        emit(
            sink,
            SpeedProgress::Phase {
                phase: SpeedPhase::PickingServer,
            },
        )
        .await?;
        let pick = self.pick_server(candidates, &options.pick, cancel).await?;
        let server = pick.best().cloned().ok_or(SpeedError::NoServer)?;

        emit(
            sink,
            SpeedProgress::Phase {
                phase: SpeedPhase::ServerInfo,
            },
        )
        .await?;
        let info = match self.server_info(&server, cancel).await {
            Ok(info) => Some(info),
            Err(SpeedError::Cancelled) => return Err(SpeedError::Cancelled),
            Err(error) => {
                tracing::debug!(%error, "speed server /info failed; continuing without limits");
                None
            }
        };

        let latency = match &options.latency {
            Some(opts) => Some(self.latency(&server, opts, cancel, sink).await?),
            None => None,
        };
        let download = match &options.download {
            Some(opts) => Some(
                self.download(&server, info.as_ref(), opts, cancel, sink)
                    .await?,
            ),
            None => None,
        };
        // A download-only provider (a static mirror) cannot take the upload: it is measured against the
        // fastest probed server that can, and the result says which one that was.
        let mut upload_server = None;
        let upload = match &options.upload {
            Some(opts) => {
                let target = if server.supports_upload() {
                    Some((server.clone(), info.clone()))
                } else {
                    match best_upload_capable(&pick.probes) {
                        Some(other) => {
                            let other_info = match self.server_info(&other, cancel).await {
                                Ok(info) => Some(info),
                                Err(SpeedError::Cancelled) => return Err(SpeedError::Cancelled),
                                Err(_) => None,
                            };
                            upload_server = Some(ServerSummary::new(&other, other_info.as_ref()));
                            Some((other, other_info))
                        }
                        None => None,
                    }
                };
                match target {
                    Some((target, target_info)) => Some(
                        self.upload(&target, target_info.as_ref(), opts, cancel, sink)
                            .await?,
                    ),
                    None => None,
                }
            }
            None => None,
        };
        Ok(SpeedResult {
            started_at_unix_ms,
            server: ServerSummary::new(&server, info.as_ref()),
            source_ip: info.as_ref().and_then(ServerInfo::client_ip_addr),
            servers_probed: pick.probes,
            latency,
            download,
            upload,
            upload_server,
        })
    }
}

/// The lowest-latency live probe that takes uploads.
fn best_upload_capable(probes: &[super::result::ServerProbe]) -> Option<ServerEndpoint> {
    probes
        .iter()
        .filter(|p| p.server.supports_upload())
        .filter_map(|p| p.latency_ms.map(|ms| (ms, &p.server)))
        .min_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(_, server)| server.clone())
}

/// Deliver a progress event; a vanished receiver cancels the run.
pub(crate) async fn emit<S: Sink<SpeedProgress>>(
    sink: &mut S,
    event: SpeedProgress,
) -> Result<(), SpeedError> {
    if sink.deliver(event).await {
        Ok(())
    } else {
        Err(SpeedError::Cancelled)
    }
}
