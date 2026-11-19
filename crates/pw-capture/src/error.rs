// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
use std::path::PathBuf;

/// Every failure of this crate. A capture backend being *absent* is not an error at startup (see
/// [`crate::select_backend`]); it only becomes one when somebody tries to open an unavailable backend.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("capture backend unavailable: {reason}")]
    Unavailable { reason: String },
    #[error("administrator rights are required to capture packets")]
    AccessDenied,
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),
    #[error("capture is not supported here: {0}")]
    Unsupported(&'static str),
    #[error("invalid capture settings: {0}")]
    InvalidSettings(String),
    #[error("capture source failed: {0}")]
    Source(String),
    #[error("i/o error on {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("i/o error: {0}")]
    Os(#[from] io::Error),
    #[error("pcapng write failed: {0}")]
    Pcapng(String),
    #[error("capture thread panicked")]
    ThreadPanicked,
}

impl CaptureError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
