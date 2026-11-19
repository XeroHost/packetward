// SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed envelope, payload or arguments.
    BadRequest,
    /// A request other than `session.hello` arrived before the handshake.
    NotHandshaken,
    /// Client and agent protocol majors differ.
    VersionMismatch,
    UnknownMethod,
    UnknownTopic,
    /// The frame exceeded the maximum size.
    FrameTooLarge,
    /// Too many jobs of this kind are running.
    Busy,
    /// The requested probe mode cannot run on this machine (UDP/TCP MTR without a capture backend).
    ModeUnavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ErrorPayload {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorPayload {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_use_snake_case() {
        let json =
            serde_json::to_string(&ErrorPayload::new(ErrorCode::VersionMismatch, "x")).unwrap();
        assert_eq!(json, r#"{"code":"version_mismatch","message":"x"}"#);
    }
}
