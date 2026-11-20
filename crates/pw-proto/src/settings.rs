// SPDX-License-Identifier: GPL-3.0-or-later
//! Agent settings (M11) and the audit log viewer.

use serde::{Deserialize, Serialize};

/// Settings of the agent, as shown by the Settings page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AgentSettingsView {
    /// The proxy saved in the settings (`http://`, `https://`, `socks5://`); absent = the system proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub proxy: Option<String>,
    /// The proxy the running agent was started with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub applied_proxy: Option<String>,
    /// The saved proxy or its credentials differ from the running ones: restart the PacketWard service to apply them.
    pub restart_required: bool,
    /// Proxy credentials are stored in the Windows Credential Manager. The password is never returned.
    #[serde(default)]
    pub proxy_credentials: bool,
    /// The stored proxy user name, if any (shown so the user can see what is saved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub proxy_username: Option<String>,
}

/// Payload of `settings.set_proxy`; an absent proxy goes back to the system proxy (and removes any stored
/// credentials). The URL never carries credentials: they travel here and are kept only in the Windows
/// Credential Manager.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct ProxyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub proxy: Option<String>,
    /// New proxy user name (at most 256 bytes, no control characters). Absent keeps the stored one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub username: Option<String>,
    /// New proxy password (at most 512 bytes, no control characters). Absent keeps the stored one; it needs a
    /// user name (sent now or already stored).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub password: Option<String>,
    /// Remove the stored credentials (wins over `username` / `password`).
    #[serde(default)]
    pub clear_credentials: bool,
}

// The credentials must never reach a log: no derived Debug.
impl std::fmt::Debug for ProxyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRequest")
            // A user may paste `http://user:pw@host` here before it is refused: do not print it either.
            .field("proxy", &self.proxy.as_ref().map(|_| "<redacted>"))
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("clear_credentials", &self.clear_credentials)
            .finish()
    }
}

/// Payload of `logs.audit`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AuditQuery {
    /// Newest entries returned, 1..=2000 (default 500).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub limit: Option<u32>,
    /// Keep only entries whose actor, action, target, detail or result contain this text (case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts-export", ts(optional))]
    pub search: Option<String>,
}

/// One audited action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AuditEntryView {
    #[cfg_attr(feature = "ts-export", ts(type = "number"))]
    pub unix_ms: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub result: String,
}

/// Reply to `logs.audit`, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS), ts(export))]
pub struct AuditView {
    pub entries: Vec<AuditEntryView>,
    /// More entries matched than were returned.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_debug_never_shows_credentials_or_the_address() {
        let request = ProxyRequest {
            proxy: Some("http://user:pw@proxy:1".into()),
            username: Some("alice".into()),
            password: Some("hunter2".into()),
            clear_credentials: false,
        };
        let text = format!("{request:?}");
        for secret in ["alice", "hunter2", "user:pw", "proxy:1"] {
            assert!(!text.contains(secret), "{secret} leaked in {text}");
        }
    }

    #[test]
    fn an_old_client_request_without_credentials_still_parses() {
        let request: ProxyRequest = serde_json::from_str(r#"{"proxy":"http://p:1"}"#).unwrap();
        assert_eq!(request.proxy.as_deref(), Some("http://p:1"));
        assert!(request.username.is_none() && request.password.is_none());
        assert!(!request.clear_credentials);
        let empty: ProxyRequest = serde_json::from_str("{}").unwrap();
        assert!(empty.proxy.is_none());
    }

    #[test]
    fn the_view_never_carries_a_password_and_an_old_agent_reply_parses() {
        let view = AgentSettingsView {
            proxy: Some("http://p:1".into()),
            applied_proxy: None,
            restart_required: true,
            proxy_credentials: true,
            proxy_username: Some("alice".into()),
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("password"));
        let old: AgentSettingsView = serde_json::from_str(r#"{"restart_required":false}"#).unwrap();
        assert!(!old.proxy_credentials && old.proxy_username.is_none());
    }
}
