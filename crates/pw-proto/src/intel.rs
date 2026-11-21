// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Threat intelligence (M8): GeoIP/ASN, blocklists and AbuseIPDB.

use serde::{Deserialize, Serialize};

/// State of the GeoIP database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GeoStatusView {
    /// `missing`, `ready` or `corrupt`.
    pub state: String,
    /// When the installed database was built (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub build_date: Option<u64>,
    /// A download is in progress.
    pub updating: bool,
    /// Why the last update failed, if it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub last_error: Option<String>,
    /// Attribution required by the database license (CC BY 4.0).
    pub attribution: String,
}

/// Payload of `intel.lookup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GeoLookupRequest {
    /// At most 500 addresses.
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GeoEntry {
    pub addr: String,
    /// ISO 3166-1 alpha-2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub country_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub as_org: Option<String>,
    /// A private or reserved address: no lookup is made for it.
    pub reserved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct GeoLookupResult {
    pub entries: Vec<GeoEntry>,
}

/// One blocklist with its toggle and last-update status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ListStatusView {
    pub id: String,
    pub name: String,
    pub description: String,
    /// The XeroHost list: signature-verified against the key pinned in the app.
    pub signed: bool,
    pub enabled: bool,
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub refresh_interval_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub last_success: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub last_error: Option<String>,
    /// Blocks in the list now (after cleaning and aggregation).
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub entries: u64,
    /// Why the list cannot be enabled (the signed list without a pinned key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub unavailable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct BlocklistsView {
    pub lists: Vec<ListStatusView>,
}

/// Payload of `intel.list.enable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ListEnableRequest {
    pub id: String,
    pub enabled: bool,
}

/// Payload of `intel.list.refresh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ListRefreshRequest {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AbuseStatusView {
    pub configured: bool,
    /// `not_configured`, `ready` or `rate_limited`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub paused_until: Option<u64>,
}

/// Payload of `intel.abuse.set_key`; an absent key removes the stored one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AbuseKeyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub key: Option<String>,
}

// The key must never reach a log: no derived Debug.
impl std::fmt::Debug for AbuseKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbuseKeyRequest")
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Payload of `intel.abuse.check`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AbuseCheckRequest {
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AbuseCheckView {
    pub addr: String,
    /// 0 – 100.
    pub score: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub usage_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub isp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub domain: Option<String>,
    pub total_reports: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub last_reported_at: Option<String>,
    pub from_cache: bool,
}
