// SPDX-License-Identifier: GPL-3.0-or-later
//! Platform-specific code. `unsafe` is only allowed in here.

#[cfg(windows)]
pub(crate) mod windows;
