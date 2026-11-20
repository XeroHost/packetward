// SPDX-License-Identifier: GPL-3.0-or-later
//! Platform-specific helpers. Everything `unsafe` in `pw-engine` lives under this module.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{free_disk_bytes, protect_dir};

/// Free bytes on the disk that holds `dir` (what a non-elevated writer could still use). `None` when the
/// system does not say; callers then rely on their own size limits only.
#[cfg(not(windows))]
pub fn free_disk_bytes(_dir: &std::path::Path) -> Option<u64> {
    None
}

/// Restricts a directory to its owner (the agent's account). On Windows the real implementation
/// grants SYSTEM and Administrators only.
#[cfg(not(windows))]
pub fn protect_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}
