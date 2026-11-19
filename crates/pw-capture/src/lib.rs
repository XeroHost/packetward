// SPDX-License-Identifier: GPL-3.0-or-later
//! pw-capture — Capture backends (Npcap, raw socket), packet decode, pcapng writer, ring buffer.
//!
//! * [`select_backend`] picks Npcap (if installed, loaded lazily) or the built-in raw-socket backend and
//!   explains what is missing; neither being present is not an error at startup.
//! * A [`CaptureBackend`] opens a [`PacketSource`]; [`Capture`] runs one on a dedicated thread, decodes to
//!   [`pw_core::PacketMeta`] and delivers batches through a bounded queue (drops are counted).
//! * [`StatsAggregator`] turns packets into per-second rates and top talkers.
//! * [`Recorder`] writes a timed capture or a ring buffer to pcapng (headers only by default).
//! * [`fake`] has sources for tests that need no network.
//!
//! Everything except the Windows adapter listing, Npcap binding and raw sockets builds and is tested on Linux.

#[cfg(test)]
mod alloc_tests;
mod backend;
mod decode;
mod error;
pub mod fake;
mod filter;
mod interfaces;
#[cfg(all(test, windows))]
mod live_tests;
mod npcap;
mod pipeline;
mod rawsock;
mod record;
mod select;
#[cfg(any(windows, test))]
mod stamp;
mod stats;
mod sys;

pub use backend::{
    BackendCaps, BackendKind, CaptureBackend, CaptureOpts, Frame, InterfaceId, LinkType,
    PacketSource, SourceEvent, DEFAULT_READ_TIMEOUT, DEFAULT_SNAPLEN,
};
pub use decode::{decode_ethernet, decode_frame, decode_ip, DecodeError, LocalAddrs};
pub use error::CaptureError;
pub use filter::{Filter, FilterError};
pub use interfaces::{
    list_interfaces, resolve_interface, InterfaceInfo, InterfaceProvider, StaticInterfaces,
    SystemInterfaces,
};
pub use npcap::{detect_npcap, npcap_dll_path, NpcapBackend, NPCAP_URL};
pub use pipeline::{
    BatchReceiver, Capture, CaptureStats, PacketBatch, PipelineConfig, StatsHandle,
};
pub use rawsock::RawSocketBackend;
pub use record::{
    Payload, RecordMode, RecordProgress, RecordSpec, Recorder, RecordingSummary, StopReason,
    DEFAULT_RING_SEGMENT_BYTES, DEFAULT_RING_TOTAL_BYTES, DEFAULT_TIMED_MAX_BYTES, FULL_SNAPLEN,
};
pub use select::{
    create_backend, create_selected_backend, select_backend, select_system_backend, Availability,
    BackendSelection, BackendStatus, CaptureEnv, Missing, MissingKind, SystemEnv,
};
pub use stats::{
    DirectionStats, ProtoStats, StatsAggregator, StatsConfig, StatsSnapshot, Talker,
    DEFAULT_MAX_TRACKED_IPS, DEFAULT_TOP_N,
};
