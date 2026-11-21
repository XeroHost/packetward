// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-ipc — IPC transport (named pipe and in-memory), framing, client/server, subscriptions.
//!
//! Layers, bottom to top:
//! * [`framing`] — 4-byte little-endian length prefix + JSON, 4 MB cap.
//! * a stream: any `AsyncRead + AsyncWrite` (named pipe in production, `memory` in tests).
//! * [`server`] — accepts streams, runs the version handshake and dispatches to a [`Handler`].
//! * [`client`] — handshake, request/response correlation and topic subscriptions.
//!
//! This crate does not depend on the engine: the agent implements [`Handler`] with `pw-engine`
//! and hands it to [`server::serve`].

#[cfg(windows)]
pub mod access;
pub mod client;
pub mod framing;
#[cfg(any(test, feature = "memory"))]
pub mod memory;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod scm;
pub mod server;
mod sys;
#[cfg(test)]
mod tests;

pub use client::{Client, ClientError, Subscription};
pub use framing::FrameError;
pub use server::{serve, serve_connection, ConnCtx, EventReceiver, Handler, Listener};
