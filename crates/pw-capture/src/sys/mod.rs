// SPDX-License-Identifier: GPL-3.0-or-later
//! Platform-specific code. `unsafe` is only allowed in here.

#[cfg(test)]
pub(crate) mod alloc_probe;
#[cfg(windows)]
pub(crate) mod npcap;
#[cfg(windows)]
pub(crate) mod windows;
