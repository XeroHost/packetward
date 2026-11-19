// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-proto — IPC and shared DTOs (serde + ts-rs). Versioned, no logic.
//!
//! Every type that crosses the agent ⇄ UI/CLI boundary lives here. With the `ts-export`
//! feature the types also derive `ts_rs::TS`; `cargo test -p pw-proto --features ts-export`
//! regenerates `apps/desktop/src/types/generated`.

mod envelope;
mod error;
mod handshake;
mod live;
mod subscribe;
mod system;

pub use envelope::{Envelope, Kind, ShapeError, ENVELOPE_VERSION, MAX_FRAME_BYTES};
pub use error::{ErrorCode, ErrorPayload};
pub use handshake::{ClientKind, HelloRequest, HelloResponse, PROTOCOL_MAJOR, PROTOCOL_MINOR};
pub use live::Heartbeat;
pub use subscribe::{SubscribeRequest, SubscribeResponse, UnsubscribeRequest};
pub use system::SystemInfo;

/// Request method names.
pub mod method {
    /// Must be the first request on every connection.
    pub const HELLO: &str = "session.hello";
    pub const SYSTEM_INFO: &str = "system.info";
    pub const SUBSCRIBE: &str = "subscribe";
    pub const UNSUBSCRIBE: &str = "unsubscribe";
}

/// Server-push topic names.
pub mod topic {
    /// One event per second while subscribed; proves the agent is alive.
    pub const LIVE_HEARTBEAT: &str = "live.heartbeat";
}
