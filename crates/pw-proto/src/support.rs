// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Support bundle (M4): a local zip the user attaches to a ticket. Built by the agent, previewed
//! first, then handed to the client in chunks so the client saves it in its own folder.

use serde::{Deserialize, Serialize};

/// Payload of `support.bundle.preview` and `support.bundle.create`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportBundleRequest {
    /// Replace this machine's own addresses and name with placeholders in the text files. The packet
    /// capture cannot be anonymized, so it is left out when this is on.
    pub anonymize_local_ips: bool,
    /// Seconds of traffic to record into the bundle (headers only); 0 = none. At most 120.
    pub capture_secs: u32,
    /// Include the last 24 hours of the agent log.
    pub include_logs: bool,
}

/// One file of the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportItem {
    pub name: String,
    /// What it contains and why support wants it.
    pub description: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    /// The start of a text file, exactly as it will be saved. Absent for binary files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub sample: Option<String>,
}

/// Reply to `support.bundle.preview`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportPreview {
    pub items: Vec<SupportItem>,
    /// Local addresses that will be replaced (0 when not anonymizing).
    pub local_addrs_hidden: u32,
}

/// Reply to `support.bundle.create`: the finished zip, waiting on the agent to be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportBundleInfo {
    pub id: String,
    /// Suggested file name, `packetward-support-<date>.zip`.
    pub name: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    pub items: Vec<SupportItem>,
}

/// Payload of `support.bundle.read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportReadRequest {
    pub id: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub offset: u64,
    /// Most bytes to return (capped by the agent at 512 KiB).
    pub len: u32,
}

/// Reply to `support.bundle.read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportChunk {
    /// Standard base64.
    pub data_b64: String,
    /// This chunk reaches the end of the file.
    pub eof: bool,
}

/// Reply of the desktop shell's `support_bundle_save` command (not an agent method).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SavedBundle {
    /// Where the zip was saved, in the current user's Documents folder.
    pub path: String,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub bytes: u64,
    pub items: Vec<SupportItem>,
}

/// Payload of `support.bundle.discard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct SupportDiscardRequest {
    pub id: String,
}
