// SPDX-License-Identifier: GPL-3.0-or-later
//! The speed-test client (ARCHITECTURE §6.6): latency/jitter, multi-stream download and upload, bin tests, server
//! picker. It talks to `tools/speed-server` (`/ping`, `/download?bytes=N`, `POST /upload`, `/info`).
//!
//! # Layout
//!
//! | Piece | Entry point |
//! |---|---|
//! | Servers | [`SpeedNode`], [`ServerEndpoint`], [`Candidates`] (node list + custom URLs; the empty list is valid) |
//! | Orchestration | [`SpeedClient`]: [`pick_server`](SpeedClient::pick_server), [`latency`](SpeedClient::latency), [`download`](SpeedClient::download), [`upload`](SpeedClient::upload), [`bin_test`](SpeedClient::bin_test), [`run`](SpeedClient::run) |
//! | Network seam | [`SpeedTransport`]; real: `HttpTransport` (feature `speed`); test: [`fake::FakeTransport`] |
//! | Arithmetic | [`math`] (warm-up exclusion, 1-second buckets, peak, jitter), pure functions |
//! | Budget | [`UsageLedger`] against the server's published per-IP byte budgets |
//!
//! # Conventions
//!
//! * Cancellation uses the crate's [`CancelToken`](crate::CancelToken). Cancelling drops every in-flight request
//!   (the connection closes), and the call returns [`SpeedError::Cancelled`] only after all streams are gone: no
//!   byte moves afterwards.
//! * Progress goes to a [`Sink`](crate::Sink) (bounded `mpsc::Sender`, closure, or `NullSink`) as
//!   [`SpeedProgress`], one event per bucket. A sink whose receiver is gone counts as a cancellation.
//! * All parallel streams of one run send the same `?test=<id>` so the server counts them as one test.
//! * Data is never stored: downloads are counted and discarded, uploads are generated from one reusable buffer.
//! * A 429 fails the run at once ([`SpeedError::RateLimited`] with the server's `Retry-After`); nothing is retried.
//! * `https` for nodes; `http` only for an explicit custom server. No telemetry, no third-party lookups: the
//!   source IP comes from the chosen server's `/info`.

mod bin;
mod client;
mod error;
pub mod fake;
#[cfg(feature = "speed")]
mod http;
mod latency;
mod ledger;
pub mod math;
mod picker;
pub mod providers;
mod result;
mod server;
mod throughput;
mod transport;

pub use bin::{BinOptions, BinSize};
pub use client::{RunOptions, SpeedClient};
pub use error::{BudgetWindow, SpeedError, TransportError};
#[cfg(feature = "speed")]
pub use http::{HttpTransport, HttpTransportConfig};
pub use latency::LatencyOptions;
pub use ledger::UsageLedger;
pub use picker::{PickOptions, PickResult};
pub use result::{
    BinResult, Direction, LatencyResult, ServerProbe, ServerSummary, SpeedPhase, SpeedProgress,
    SpeedResult, ThroughputResult,
};
pub use server::{
    new_test_id, valid_test_id, Candidates, RejectedServer, Scheme, ServerEndpoint, ServerInfo,
    ServerKind, ServerLimits, SpeedNode,
};
pub use throughput::ThroughputOptions;
pub use transport::{ByteMeter, DownloadRequest, SpeedTransport, UploadRequest};

#[cfg(test)]
mod tests;
