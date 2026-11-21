// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Platform-specific code. `unsafe` is only allowed in here.

#[cfg(windows)]
pub(crate) mod windows;
