// SPDX-License-Identifier: GPL-3.0-or-later
//! Latency and jitter: sequential `/ping` round trips.

use std::time::Duration;

use crate::{CancelToken, Sink};

use super::client::{emit, SpeedClient};
use super::error::{SpeedError, TransportError};
use super::math::latency_stats;
use super::result::{LatencyResult, SpeedPhase, SpeedProgress};
use super::server::ServerEndpoint;
use super::transport::SpeedTransport;

/// Latency test options. Out-of-range values are clamped.
#[derive(Debug, Clone)]
pub struct LatencyOptions {
    /// Measured pings, 1..=100. Default 10.
    pub count: u32,
    /// Timeout of one ping, 100 ms..=10 s. A ping that times out counts as lost.
    pub timeout: Duration,
    /// Pause between pings, at most 2 s.
    pub interval: Duration,
    /// Send one unmeasured ping first so the TCP/TLS handshake is not part of the first sample.
    pub warm_up_ping: bool,
}

impl Default for LatencyOptions {
    fn default() -> Self {
        Self {
            count: 10,
            timeout: Duration::from_secs(2),
            interval: Duration::from_millis(50),
            warm_up_ping: true,
        }
    }
}

impl LatencyOptions {
    fn normalized(&self) -> Self {
        Self {
            count: self.count.clamp(1, 100),
            timeout: self
                .timeout
                .clamp(Duration::from_millis(100), Duration::from_secs(10)),
            interval: self.interval.min(Duration::from_secs(2)),
            warm_up_ping: self.warm_up_ping,
        }
    }
}

impl<T: SpeedTransport> SpeedClient<T> {
    /// `count` pings, one at a time. Failed pings are counted as lost; the call itself only fails when cancelled
    /// or when the server answers 429 (fail fast, no retry).
    pub async fn latency<S: Sink<SpeedProgress>>(
        &self,
        server: &ServerEndpoint,
        options: &LatencyOptions,
        cancel: &CancelToken,
        sink: &mut S,
    ) -> Result<LatencyResult, SpeedError> {
        let options = options.normalized();
        emit(
            sink,
            SpeedProgress::Phase {
                phase: SpeedPhase::Latency,
            },
        )
        .await?;
        if options.warm_up_ping {
            // Result ignored on purpose: it only opens the connection. A 429 will show on the measured pings.
            let _ = self.ping_once(server, options.timeout, cancel).await;
            if cancel.is_cancelled() {
                return Err(SpeedError::Cancelled);
            }
        }
        let mut samples = Vec::with_capacity(options.count as usize);
        for seq in 1..=options.count {
            let rtt = match self.ping_once(server, options.timeout, cancel).await {
                Ok(rtt) => Some(rtt.as_secs_f64() * 1000.0),
                Err(SpeedError::Cancelled) => return Err(SpeedError::Cancelled),
                Err(error @ SpeedError::RateLimited { .. }) => return Err(error),
                Err(error) => {
                    tracing::debug!(%error, seq, "speed ping failed");
                    None
                }
            };
            samples.push(rtt);
            emit(sink, SpeedProgress::Ping { seq, rtt_ms: rtt }).await?;
            if seq < options.count && !options.interval.is_zero() {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Err(SpeedError::Cancelled),
                    () = tokio::time::sleep(options.interval) => {}
                }
            }
        }
        Ok(latency_stats(&samples))
    }

    async fn ping_once(
        &self,
        server: &ServerEndpoint,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Result<Duration, SpeedError> {
        let attempt = async {
            // The transport enforces `timeout` itself; this outer bound also covers a transport that does not.
            match tokio::time::timeout(timeout * 2, self.transport.ping(server, timeout)).await {
                Ok(result) => result,
                Err(_) => Err(TransportError::Timeout),
            }
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(SpeedError::Cancelled),
            result = attempt => result.map_err(SpeedError::from),
        }
    }
}
