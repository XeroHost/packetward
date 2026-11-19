// SPDX-License-Identifier: GPL-3.0-or-later
//! In-app updates (Tauri updater against GitHub Releases), with two channels.
//!
//! * `stable`: `latest.json` of the newest non-pre-release GitHub release.
//! * `beta`: `latest.json` attached to the rolling `updater-beta` pre-release, which the release
//!   workflow overwrites on every beta *and* every stable release, so a beta user also sees a stable
//!   release that supersedes the beta they run.
//!
//! The updater fails closed. The plugin is only registered when `plugins.updater.pubkey` in
//! `tauri.conf.json` is a valid minisign public key (the committed placeholder is not), and every
//! command answers `not configured` without touching the network otherwise. Nothing here ever
//! checks by itself: the UI asks, and only when the user switched "check at start" on or pressed the
//! button. The plugin's own JavaScript commands are never granted to the webview (no `updater:*`
//! permission in the capability), so the webview can only use the commands below.

use std::sync::Mutex;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tauri::{AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};

const STABLE_ENDPOINT: &str =
    "https://github.com/XeroHost/packetward/releases/latest/download/latest.json";
const BETA_ENDPOINT: &str =
    "https://github.com/XeroHost/packetward/releases/download/updater-beta/latest.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Stable,
    Beta,
}

impl UpdateChannel {
    fn endpoint(self) -> &'static str {
        match self {
            UpdateChannel::Stable => STABLE_ENDPOINT,
            UpdateChannel::Beta => BETA_ENDPOINT,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("updates are not configured in this build (no updater public key)")]
    NotConfigured,
    #[error("there is no update to install; check for updates first")]
    NothingPending,
    #[error("an update is already being installed")]
    Busy,
    #[error("{0}")]
    Updater(String),
}

// Tauri commands need a serializable error; the UI only displays the message.
impl Serialize for UpdateError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<tauri_plugin_updater::Error> for UpdateError {
    fn from(err: tauri_plugin_updater::Error) -> Self {
        UpdateError::Updater(err.to_string())
    }
}

/// Whether the updater may be used, plus the update found by the last check.
pub struct UpdaterState {
    configured: bool,
    pending: Mutex<Option<Update>>,
    installing: Mutex<bool>,
}

impl UpdaterState {
    pub fn new(configured: bool) -> Self {
        Self {
            configured,
            pending: Mutex::new(None),
            installing: Mutex::new(false),
        }
    }
}

/// True when `pubkey` is the base64 of a minisign public key file, the format the Tauri CLI writes
/// and the updater plugin decodes. The placeholder, an empty string or any other text is not.
pub fn pubkey_is_valid(pubkey: &str) -> bool {
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(pubkey.trim()) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    minisign_verify::PublicKey::decode(text).is_ok()
}

/// Reads `plugins.updater.pubkey` from the app configuration and validates it.
pub fn is_configured(config: &tauri::Config) -> bool {
    config
        .plugins
        .0
        .get("updater")
        .and_then(|value| value.get("pubkey"))
        .and_then(|value| value.as_str())
        .is_some_and(pubkey_is_valid)
}

/// What the Settings page shows without any network access.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub configured: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum UpdateCheck {
    /// No usable public key in this build: nothing was requested from the network.
    NotConfigured,
    UpToDate {
        current_version: String,
    },
    #[serde(rename_all = "camelCase")]
    Available {
        current_version: String,
        version: String,
        notes: Option<String>,
        /// RFC 3339, when the release metadata carries it.
        date: Option<String>,
    },
}

/// Progress of `update_install`, streamed to the UI.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "camelCase")]
pub enum InstallEvent {
    #[serde(rename_all = "camelCase")]
    Progress { downloaded: u64, total: Option<u64> },
    /// The signature was verified and the installer is being started; Windows closes the app.
    Installing,
}

#[tauri::command]
pub fn update_info(app: AppHandle, state: State<'_, UpdaterState>) -> UpdateInfo {
    UpdateInfo {
        current_version: app.package_info().version.to_string(),
        configured: state.configured,
    }
}

/// Asks the channel's `latest.json` whether a newer version exists. The only network call of the
/// updater besides the download itself.
#[tauri::command]
pub async fn update_check(
    app: AppHandle,
    state: State<'_, UpdaterState>,
    channel: UpdateChannel,
) -> Result<UpdateCheck, UpdateError> {
    if !state.configured {
        return Ok(UpdateCheck::NotConfigured);
    }
    let endpoint = tauri::Url::parse(channel.endpoint())
        .map_err(|err| UpdateError::Updater(err.to_string()))?;
    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])?
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let found = updater.check().await?;
    let current_version = app.package_info().version.to_string();
    let result = match &found {
        Some(update) => UpdateCheck::Available {
            current_version,
            version: update.version.clone(),
            notes: update.body.clone(),
            date: update.date.map(|d| d.to_string()),
        },
        None => UpdateCheck::UpToDate { current_version },
    };
    *state.pending.lock().unwrap_or_else(|e| e.into_inner()) = found;
    Ok(result)
}

/// Downloads the update found by the last check, verifies its signature against the pinned public
/// key and starts the installer. On Windows the app exits when the installer starts; the installer
/// stops the service before replacing files and starts it again afterwards.
#[tauri::command]
pub async fn update_install(
    state: State<'_, UpdaterState>,
    on_event: Channel<InstallEvent>,
) -> Result<(), UpdateError> {
    if !state.configured {
        return Err(UpdateError::NotConfigured);
    }
    let update = state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .ok_or(UpdateError::NothingPending)?;
    {
        let mut installing = state.installing.lock().unwrap_or_else(|e| e.into_inner());
        if *installing {
            return Err(UpdateError::Busy);
        }
        *installing = true;
    }
    let mut downloaded: u64 = 0;
    let progress = on_event.clone();
    let result = update
        .download_and_install(
            move |chunk, total| {
                downloaded = downloaded.saturating_add(chunk as u64);
                let _ = progress.send(InstallEvent::Progress { downloaded, total });
            },
            || {
                let _ = on_event.send(InstallEvent::Installing);
            },
        )
        .await;
    *state.installing.lock().unwrap_or_else(|e| e.into_inner()) = false;
    result.map_err(UpdateError::from)
}

/// Builds the plugin registration and the shared state. Call once while building the app.
pub fn register<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    config: &tauri::Config,
) -> tauri::Builder<R> {
    let configured = is_configured(config);
    if configured {
        tracing::info!("updater enabled");
    } else {
        tracing::info!("updater not configured (no valid public key); update features are off");
    }
    let builder = builder.manage(UpdaterState::new(configured));
    if configured {
        builder.plugin(tauri_plugin_updater::Builder::new().build())
    } else {
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Committed in `tauri.conf.json` until the owner generates the key (docs/RELEASE-KEYS.md).
    const PUBKEY_PLACEHOLDER: &str = "REPLACE_WITH_UPDATER_PUBLIC_KEY";

    // Public key from the updater plugin's own tests (public data, not a key of this project).
    const TEST_PUBKEY: &str = "untrusted comment: minisign public key: A49EF4746FA6E6D7\nRWTX5qZvdPSepDGWg2bz8n6ArQnBMwgQK1geVosorcbLzcunD+KJ+cYe";

    fn encoded(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    #[test]
    fn placeholder_and_junk_are_not_keys() {
        assert!(!pubkey_is_valid(PUBKEY_PLACEHOLDER));
        assert!(!pubkey_is_valid(""));
        assert!(!pubkey_is_valid("   "));
        assert!(!pubkey_is_valid("not base64 at all!"));
        assert!(!pubkey_is_valid(&encoded("just some text")));
        assert!(!pubkey_is_valid(TEST_PUBKEY)); // the raw file, not its base64
    }

    #[test]
    fn a_minisign_public_key_file_in_base64_is_accepted() {
        assert!(pubkey_is_valid(&encoded(TEST_PUBKEY)));
        assert!(pubkey_is_valid(&format!("{}\n", encoded(TEST_PUBKEY))));
    }

    #[test]
    fn channels_use_https_endpoints_on_the_project_repository() {
        for channel in [UpdateChannel::Stable, UpdateChannel::Beta] {
            let url = tauri::Url::parse(channel.endpoint()).expect("valid url");
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some("github.com"));
            assert!(url.path().starts_with("/XeroHost/packetward/releases/"));
            assert!(url.path().ends_with("/latest.json"));
        }
        assert_ne!(
            UpdateChannel::Stable.endpoint(),
            UpdateChannel::Beta.endpoint()
        );
    }

    #[test]
    fn channel_wire_format_is_lowercase() {
        assert_eq!(
            serde_json::to_string(&UpdateChannel::Beta).unwrap(),
            "\"beta\""
        );
        assert_eq!(
            serde_json::from_str::<UpdateChannel>("\"stable\"").unwrap(),
            UpdateChannel::Stable
        );
        assert!(serde_json::from_str::<UpdateChannel>("\"nightly\"").is_err());
    }

    #[test]
    fn check_results_serialize_for_the_ui() {
        let json = serde_json::to_value(UpdateCheck::NotConfigured).unwrap();
        assert_eq!(json["state"], "notConfigured");
        let json = serde_json::to_value(UpdateCheck::Available {
            current_version: "0.1.0".into(),
            version: "0.2.0".into(),
            notes: None,
            date: None,
        })
        .unwrap();
        assert_eq!(json["state"], "available");
        assert_eq!(json["currentVersion"], "0.1.0");
        assert_eq!(json["version"], "0.2.0");
    }

    #[test]
    fn the_committed_key_is_the_placeholder_or_a_real_key_never_garbage() {
        let config: tauri::Config = serde_json::from_str(include_str!("../tauri.conf.json"))
            .expect("tauri.conf.json parses as a tauri config");
        let pubkey = config
            .plugins
            .0
            .get("updater")
            .and_then(|v| v.get("pubkey"))
            .and_then(|v| v.as_str())
            .expect("plugins.updater.pubkey exists (the plugin needs it to initialise)");
        assert!(pubkey == PUBKEY_PLACEHOLDER || pubkey_is_valid(pubkey));
        assert_eq!(is_configured(&config), pubkey != PUBKEY_PLACEHOLDER);
    }
}
