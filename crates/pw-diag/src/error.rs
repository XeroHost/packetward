// SPDX-License-Identifier: GPL-3.0-or-later
//! Error type shared by the diagnostics modules.

use thiserror::Error;

/// Why a diagnostic could not run (as opposed to a diagnostic *result* such as "host down").
#[derive(Debug, Error)]
pub enum DiagError {
    /// The request was refused before anything was sent (bad port, empty host, ...).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The ICMP API is not available on this platform (the Win32 backend only exists on Windows).
    #[error("{0} is not supported on this platform")]
    Unsupported(&'static str),
    /// The operating system refused or failed the operation.
    #[error("system error {code}: {message}")]
    System {
        /// Win32 / errno style code.
        code: u32,
        /// Short human readable context.
        message: String,
    },
    /// I/O error from a socket.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
