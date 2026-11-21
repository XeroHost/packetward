// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Platform-specific part of UDP / TCP-SYN probes (sockets with a chosen TTL). `unsafe` is only
//! allowed in `windows.rs`.

#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
pub use unsupported::UnsupportedSender as SocketSender;
#[cfg(windows)]
pub use windows::WindowsSender as SocketSender;
