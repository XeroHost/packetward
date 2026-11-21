// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Platform-specific code. `unsafe` is only allowed in here.

#[cfg(not(windows))]
pub(crate) mod unsupported;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(not(windows))]
pub use unsupported::UnsupportedPinger as SystemPinger;
#[cfg(windows)]
pub use windows::WindowsPinger as SystemPinger;
