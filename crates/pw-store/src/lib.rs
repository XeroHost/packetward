// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-store — SQLite storage: audit log, blocks, alerts, settings, RDP trust set, intel cache.
//!
//! A small synchronous layer over `rusqlite`. [`Store`] is `Send + Sync` (one connection behind a
//! mutex; every method is short). Nothing here reads the clock: functions that depend on time take
//! an explicit `now_ms` (Unix milliseconds), so tests are deterministic. The one exception is the
//! timestamp in the `.corrupt-<unix>` name of a recovered database file.
//!
//! The database and its `-wal`/`-shm` files must not be readable by non-administrators: the store
//! does not change permissions, the caller protects the folder (see [`Store::open_private`]).

#![forbid(unsafe_code)]

mod alerts;
mod audit;
mod blocks;
mod error;
mod intel;
mod kv;
mod rdp;
mod schema;
mod store;

pub use alerts::{AlertMetricRecord, AlertPhase, AlertRecord, AlertSeverity, AlertsPruned};
pub use audit::{
    AuditActor, AuditEntry, AuditQuery, AuditResult, NewAudit, MAX_ACTION_BYTES, MAX_DETAIL_BYTES,
    MAX_QUERY_LIMIT, MAX_TARGET_BYTES,
};
pub use blocks::{BlockRecord, BlockSource};
pub use error::{Result, StoreError};
pub use kv::{MAX_KEY_BYTES, MAX_VALUE_BYTES};
pub use rdp::RdpLogon;
pub use schema::SCHEMA_VERSION;
pub use store::{Limits, Opened, Recovery, Store};
