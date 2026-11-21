// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Server picker: measure every candidate in parallel with a short timeout and choose the lowest latency.

use std::time::Duration;

use tokio::task::JoinSet;

use crate::CancelToken;

use super::client::SpeedClient;
use super::error::SpeedError;
use super::result::ServerProbe;
use super::server::ServerEndpoint;
use super::transport::SpeedTransport;

/// More candidates than this are ignored (a custom list is user input; this bounds the parallel probes).
pub const MAX_CANDIDATES: usize = 64;

/// How to probe candidates.
#[derive(Debug, Clone)]
pub struct PickOptions {
    /// Pings per candidate (the best one counts). Clamped to 1..=10.
    pub probes: u32,
    /// Timeout of each ping. Clamped to 200 ms..=10 s.
    pub timeout: Duration,
}

impl Default for PickOptions {
    fn default() -> Self {
        Self {
            probes: 3,
            // A first request opens TCP and TLS: a mirror on another continent needs over a second.
            timeout: Duration::from_millis(3000),
        }
    }
}

impl PickOptions {
    fn normalized(&self) -> Self {
        Self {
            probes: self.probes.clamp(1, 10),
            timeout: self
                .timeout
                .clamp(Duration::from_millis(200), Duration::from_secs(10)),
        }
    }
}

/// Every candidate with its latency (input order) and the winner.
#[derive(Debug, Clone, PartialEq)]
pub struct PickResult {
    /// One entry per candidate, in the order given.
    pub probes: Vec<ServerProbe>,
    /// Index into `probes` of the lowest-latency live candidate (the first one on a tie); `None` when the list is
    /// empty or every candidate is dead.
    pub best: Option<usize>,
}

impl PickResult {
    /// The chosen server.
    pub fn best(&self) -> Option<&ServerEndpoint> {
        self.best
            .and_then(|i| self.probes.get(i))
            .map(|p| &p.server)
    }
}

impl<T: SpeedTransport> SpeedClient<T> {
    /// Ping all `candidates` in parallel and pick the fastest. An empty list is valid and yields no winner. A
    /// candidate that never answers is dead and skipped (its [`ServerProbe::error`] says why). Only cancellation
    /// is an error.
    pub async fn pick_server(
        &self,
        candidates: &[ServerEndpoint],
        options: &PickOptions,
        cancel: &CancelToken,
    ) -> Result<PickResult, SpeedError> {
        let options = options.normalized();
        let candidates = if candidates.len() > MAX_CANDIDATES {
            tracing::warn!(
                count = candidates.len(),
                "too many speed-test candidates; only the first {MAX_CANDIDATES} are probed"
            );
            &candidates[..MAX_CANDIDATES]
        } else {
            candidates
        };
        let mut set = JoinSet::new();
        for (index, server) in candidates.iter().enumerate() {
            let transport = std::sync::Arc::clone(&self.transport);
            let server = server.clone();
            let options = options.clone();
            set.spawn(async move {
                let mut best: Option<f64> = None;
                let mut last_error = None;
                // A mirror rate-limits quick repeats (and drops connections when it is annoyed): one answer
                // is enough to rank it, a second try only after a failure.
                let mirror = server.kind == super::server::ServerKind::Mirror;
                let probes = if mirror { 2 } else { options.probes };
                for _ in 0..probes {
                    match transport.ping(&server, options.timeout).await {
                        Ok(rtt) => {
                            let ms = rtt.as_secs_f64() * 1000.0;
                            best = Some(best.map_or(ms, |b| b.min(ms)));
                            if mirror {
                                break;
                            }
                        }
                        Err(error) => last_error = Some(error.to_string()),
                    }
                }
                (index, best, last_error)
            });
        }
        let mut probes: Vec<ServerProbe> = candidates
            .iter()
            .map(|server| ServerProbe {
                server: server.clone(),
                latency_ms: None,
                error: Some("no answer".to_owned()),
            })
            .collect();
        loop {
            let joined = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                    return Err(SpeedError::Cancelled);
                }
                joined = set.join_next() => joined,
            };
            match joined {
                None => break,
                Some(Ok((index, Some(ms), _))) => {
                    probes[index].latency_ms = Some(ms);
                    probes[index].error = None;
                }
                Some(Ok((index, None, error))) => {
                    probes[index].error = error.or_else(|| Some("no answer".to_owned()));
                }
                Some(Err(error)) => tracing::debug!(%error, "speed probe task failed"),
            }
        }
        let best = probes
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.latency_ms.map(|ms| (i, ms)))
            .min_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)))
            .map(|(i, _)| i);
        Ok(PickResult { probes, best })
    }
}
