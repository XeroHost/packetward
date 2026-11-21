// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Agent settings that survive restarts (`settings.json` in the agent data folder). Today: the proxy
//! used by the agent's outbound HTTP calls (speed test, GeoIP and blocklist downloads, AbuseIPDB). The
//! desktop updater has its own transport and uses the Windows system proxy. The proxy is read once when
//! the agent starts, so a change needs a service restart.
//!
//! The proxy URL never carries credentials. An optional user name and password for the proxy live only
//! in the OS credential store (`proxy-username` / `proxy-password`), never in `settings.json`, a log, an
//! error message or a `Debug` print.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pw_core::{validate_proxy_password, validate_proxy_username, ProxyAuth};
use pw_intel::secret::{PROXY_PASSWORD_NAME, PROXY_USERNAME_NAME};
use pw_intel::{Secret, SecretError, SecretStore};
use pw_proto::{AgentSettingsView, ErrorCode, ErrorPayload, ProxyRequest};
use serde::{Deserialize, Serialize};

const FILE: &str = "settings.json";
const MAX_PROXY_LEN: usize = 256;

/// What a `settings.set_proxy` call did to the stored credentials (for the audit log; never the values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialChange {
    Unchanged,
    Saved,
    Removed,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    proxy: Option<String>,
    /// `None` = never chosen = on.
    capture_on_start: Option<bool>,
}

pub struct SettingsStore {
    path: Option<PathBuf>,
    saved: Mutex<Saved>,
    secrets: Arc<dyn SecretStore>,
    /// The stored proxy credentials (`None` when there are none or no proxy is set).
    auth: Mutex<Option<ProxyAuth>>,
    /// The proxy the running agent was started with.
    applied_proxy: Option<String>,
    /// The credentials the running agent was started with.
    applied_auth: Option<ProxyAuth>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Writes `bytes` to `path` atomically: a sibling `.tmp` file first, then a rename. Shared with the
/// MCP policy (`mcp.json`), which lives in the same protected folder.
pub(crate) fn write_json_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

/// Whether the live capture should start with the agent: on unless the user switched it off.
pub fn saved_capture_on_start(dir: Option<&Path>) -> bool {
    read_saved(dir).capture_on_start.unwrap_or(true)
}

fn read_saved(dir: Option<&Path>) -> Saved {
    dir.and_then(|d| fs::read_to_string(d.join(FILE)).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// The proxy saved in `dir`, if any (read before the HTTP clients are built).
pub fn saved_proxy(dir: Option<&Path>) -> Option<String> {
    let text = fs::read_to_string(dir?.join(FILE)).ok()?;
    let saved: Saved = serde_json::from_str(&text).ok()?;
    saved.proxy.filter(|p| validate_proxy(p).is_ok())
}

/// The proxy credentials in the secret store. Both entries must exist and be valid; a missing store
/// entry or a store failure means "no credentials" (the agent keeps working without them).
pub fn load_proxy_auth(secrets: &dyn SecretStore) -> Option<ProxyAuth> {
    let read = |name: &str| match secrets.get(name) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(%err, "could not read the proxy credentials from the credential store");
            None
        }
    };
    let username = read(PROXY_USERNAME_NAME)?;
    let password = read(PROXY_PASSWORD_NAME)?;
    if validate_proxy_username(username.expose()).is_err()
        || validate_proxy_password(password.expose()).is_err()
    {
        return None;
    }
    Some(ProxyAuth::new(username.expose(), password.expose()))
}

/// The proxy credentials the HTTP clients must use: only meaningful together with a saved proxy.
#[cfg(any(windows, test))]
pub fn saved_proxy_auth(dir: Option<&Path>, secrets: &dyn SecretStore) -> Option<ProxyAuth> {
    saved_proxy(dir)?;
    load_proxy_auth(secrets)
}

/// Writes (or, with `None`, removes) both credential entries.
fn store_auth(secrets: &dyn SecretStore, auth: Option<&ProxyAuth>) -> Result<(), SecretError> {
    match auth {
        Some(auth) => {
            secrets.set(PROXY_USERNAME_NAME, &Secret::new(auth.username()))?;
            secrets.set(PROXY_PASSWORD_NAME, &Secret::new(auth.password()))
        }
        None => {
            secrets.delete(PROXY_USERNAME_NAME)?;
            secrets.delete(PROXY_PASSWORD_NAME)
        }
    }
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

/// Accepts `http://`, `https://`, `socks5://` and `socks5h://` URLs with a host and no credentials
/// (secrets never go to a plain settings file or a URL: they have their own fields).
pub fn validate_proxy(proxy: &str) -> Result<(), String> {
    if proxy.len() > MAX_PROXY_LEN || proxy.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("that is not a proxy address".to_owned());
    }
    let Some((scheme, rest)) = proxy.split_once("://") else {
        return Err("the proxy must look like http://host:port or socks5://host:port".to_owned());
    };
    if !["http", "https", "socks5", "socks5h"].contains(&scheme.to_ascii_lowercase().as_str()) {
        return Err("the proxy scheme must be http, https, socks5 or socks5h".to_owned());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(
            "the proxy address must not contain a user name or password: use the credential fields"
                .to_owned(),
        );
    }
    if authority.is_empty() || authority.starts_with(':') {
        return Err("the proxy has no host".to_owned());
    }
    Ok(())
}

impl SettingsStore {
    /// `dir`: the agent data folder (`None`: nothing is kept, as in tests).
    pub fn open(dir: Option<&Path>, secrets: Arc<dyn SecretStore>) -> Self {
        let applied_proxy = saved_proxy(dir);
        let applied_auth = applied_proxy
            .as_ref()
            .and_then(|_| load_proxy_auth(secrets.as_ref()));
        Self {
            path: dir.map(|d| d.join(FILE)),
            saved: Mutex::new(Saved {
                proxy: applied_proxy.clone(),
                capture_on_start: read_saved(dir).capture_on_start,
            }),
            secrets,
            auth: Mutex::new(applied_auth.clone()),
            applied_proxy,
            applied_auth,
        }
    }

    pub fn view(&self) -> AgentSettingsView {
        let (proxy, capture_on_start) = {
            let saved = lock(&self.saved);
            (saved.proxy.clone(), saved.capture_on_start.unwrap_or(true))
        };
        let auth = lock(&self.auth).clone();
        AgentSettingsView {
            restart_required: proxy != self.applied_proxy || auth != self.applied_auth,
            proxy,
            applied_proxy: self.applied_proxy.clone(),
            proxy_credentials: auth.is_some(),
            proxy_username: auth.map(|a| a.username().to_owned()),
            capture_on_start,
        }
    }

    /// Writes the settings file (atomically). Nothing is kept without a data folder.
    fn persist(&self, saved: &Saved) -> Result<(), ErrorPayload> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(saved).map_err(|e| {
            ErrorPayload::new(ErrorCode::Internal, format!("could not save settings: {e}"))
        })?;
        write_json_atomic(path, &bytes).map_err(|e| {
            ErrorPayload::new(ErrorCode::Internal, format!("could not save settings: {e}"))
        })
    }

    /// Chooses whether the live capture starts with the agent. It takes effect at the next agent start;
    /// the running capture is not touched (the Capture page starts and stops it).
    pub fn set_capture_on_start(&self, enabled: bool) -> Result<AgentSettingsView, ErrorPayload> {
        let mut saved = lock(&self.saved);
        saved.capture_on_start = Some(enabled);
        self.persist(&saved)?;
        drop(saved);
        Ok(self.view())
    }

    /// Credentials after applying `request` to `current`, or `None` to remove them. Validates everything
    /// before anything is written. The error messages never repeat a value.
    fn next_auth(
        request: &ProxyRequest,
        has_proxy: bool,
        current: Option<&ProxyAuth>,
    ) -> Result<Option<ProxyAuth>, ErrorPayload> {
        if !has_proxy {
            // Without an explicit proxy there is nothing to authenticate against.
            if request.username.is_some() || request.password.is_some() {
                return Err(bad_request(
                    "set a proxy address first: credentials only apply to an explicit proxy",
                ));
            }
            return Ok(None);
        }
        if request.clear_credentials {
            return Ok(None);
        }
        let username = request.username.as_deref().map(str::trim);
        // An empty user name field means "leave as it is", unless a password comes with it.
        let username = username.filter(|u| !u.is_empty() || request.password.is_some());
        if username.is_none() && request.password.is_none() {
            return Ok(current.cloned());
        }
        let username = match username {
            Some(user) => user.to_owned(),
            None => current
                .map(|a| a.username().to_owned())
                .ok_or_else(|| bad_request("a proxy password needs a user name"))?,
        };
        validate_proxy_username(&username).map_err(bad_request)?;
        let password = match &request.password {
            Some(password) => password.clone(),
            None => current
                .map(|a| a.password().to_owned())
                .ok_or_else(|| bad_request("a proxy user name needs a password"))?,
        };
        validate_proxy_password(&password).map_err(bad_request)?;
        Ok(Some(ProxyAuth::new(username, password)))
    }

    /// Saves the proxy and its credentials. The credentials go to the secret store only.
    pub fn set_proxy(
        &self,
        request: &ProxyRequest,
    ) -> Result<(AgentSettingsView, CredentialChange), ErrorPayload> {
        let proxy = request
            .proxy
            .as_ref()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty());
        if let Some(value) = &proxy {
            validate_proxy(value).map_err(bad_request)?;
        }
        let previous = lock(&self.auth).clone();
        let next = Self::next_auth(request, proxy.is_some(), previous.as_ref())?;
        let change = match (&previous, &next) {
            (a, b) if a == b => CredentialChange::Unchanged,
            (_, Some(_)) => CredentialChange::Saved,
            (_, None) => CredentialChange::Removed,
        };
        if change != CredentialChange::Unchanged {
            if let Err(err) = store_auth(self.secrets.as_ref(), next.as_ref()) {
                // Best effort: put back what was there, so the store is not left half written.
                let _ = store_auth(self.secrets.as_ref(), previous.as_ref());
                return Err(ErrorPayload::new(
                    ErrorCode::Internal,
                    format!("could not save the proxy credentials: {err}"),
                ));
            }
            *lock(&self.auth) = next;
        }
        let mut saved = lock(&self.saved);
        saved.proxy = proxy;
        self.persist(&saved)?;
        drop(saved);
        Ok((self.view(), change))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxies_are_validated() {
        for ok in [
            "http://proxy.example.com:3128",
            "https://10.0.0.1:8443/",
            "socks5://127.0.0.1:1080",
            "SOCKS5H://[::1]:1080",
        ] {
            assert!(validate_proxy(ok).is_ok(), "{ok}");
        }
        for bad in [
            "proxy.example.com:3128",
            "ftp://proxy:21",
            "http://user:secret@proxy:3128",
            "http://",
            "http://:3128",
            "http://pro xy:3128",
            "http://proxy\n:3128",
        ] {
            assert!(validate_proxy(bad).is_err(), "{bad}");
        }
        assert!(validate_proxy(&format!("http://{}", "a".repeat(300))).is_err());
    }

    use pw_intel::MemorySecretStore;

    fn memory() -> Arc<MemorySecretStore> {
        Arc::new(MemorySecretStore::new())
    }

    fn url_only(proxy: &str) -> ProxyRequest {
        ProxyRequest {
            proxy: Some(proxy.to_owned()),
            username: None,
            password: None,
            clear_credentials: false,
        }
    }

    fn with_credentials(proxy: &str, user: &str, password: &str) -> ProxyRequest {
        ProxyRequest {
            username: Some(user.to_owned()),
            password: Some(password.to_owned()),
            ..url_only(proxy)
        }
    }

    fn stored(secrets: &MemorySecretStore, name: &str) -> Option<String> {
        secrets.get(name).unwrap().map(|s| s.expose().to_owned())
    }

    #[test]
    fn a_change_is_saved_and_needs_a_restart_until_the_agent_starts_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::open(Some(dir.path()), memory());
        assert!(!store.view().restart_required);
        let (view, change) = store.set_proxy(&url_only(" http://proxy:3128 ")).unwrap();
        assert_eq!(change, CredentialChange::Unchanged);
        assert_eq!(view.proxy.as_deref(), Some("http://proxy:3128"));
        assert!(view.restart_required && view.applied_proxy.is_none());
        // The next start reads it and has nothing left to apply.
        assert_eq!(
            saved_proxy(Some(dir.path())).as_deref(),
            Some("http://proxy:3128")
        );
        let restarted = SettingsStore::open(Some(dir.path()), memory());
        assert!(!restarted.view().restart_required);
        // Going back to the system proxy is a change again.
        let none = ProxyRequest {
            proxy: None,
            ..url_only("")
        };
        assert!(restarted.set_proxy(&none).unwrap().0.restart_required);
        assert!(saved_proxy(Some(dir.path())).is_none());
    }

    #[test]
    fn a_bad_proxy_is_refused_and_nothing_changes() {
        let secrets = memory();
        let store = SettingsStore::open(None, secrets.clone());
        let err = store
            .set_proxy(&with_credentials(
                "http://user:pw@proxy:1",
                "alice",
                "hunter2",
            ))
            .unwrap_err();
        assert!(matches!(err.code, ErrorCode::BadRequest));
        assert!(!err.message.contains("pw@") && !err.message.contains("hunter2"));
        assert!(store.view().proxy.is_none());
        assert!(stored(&secrets, PROXY_USERNAME_NAME).is_none());
    }

    #[test]
    fn credentials_go_to_the_secret_store_and_never_to_the_file_or_the_view() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = memory();
        let store = SettingsStore::open(Some(dir.path()), secrets.clone());
        let (view, change) = store
            .set_proxy(&with_credentials("http://proxy:3128", "alice", "p@ss w0rd"))
            .unwrap();
        assert_eq!(change, CredentialChange::Saved);
        assert!(view.proxy_credentials && view.restart_required);
        assert_eq!(view.proxy_username.as_deref(), Some("alice"));
        assert_eq!(
            stored(&secrets, PROXY_USERNAME_NAME).as_deref(),
            Some("alice")
        );
        assert_eq!(
            stored(&secrets, PROXY_PASSWORD_NAME).as_deref(),
            Some("p@ss w0rd")
        );
        let file = fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(!file.contains("alice") && !file.contains("p@ss"), "{file}");
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("p@ss"), "{json}");
        // The next start uses them and has nothing left to apply.
        let auth = saved_proxy_auth(Some(dir.path()), secrets.as_ref()).unwrap();
        assert_eq!((auth.username(), auth.password()), ("alice", "p@ss w0rd"));
        let restarted = SettingsStore::open(Some(dir.path()), secrets.clone());
        assert!(!restarted.view().restart_required);
    }

    #[test]
    fn a_new_password_alone_or_a_new_user_name_alone_keeps_the_other_half() {
        let secrets = memory();
        let store = SettingsStore::open(None, secrets.clone());
        store
            .set_proxy(&with_credentials("http://proxy:1", "alice", "one"))
            .unwrap();
        let only_password = ProxyRequest {
            password: Some("two".into()),
            ..url_only("http://proxy:1")
        };
        store.set_proxy(&only_password).unwrap();
        assert_eq!(
            stored(&secrets, PROXY_USERNAME_NAME).as_deref(),
            Some("alice")
        );
        assert_eq!(
            stored(&secrets, PROXY_PASSWORD_NAME).as_deref(),
            Some("two")
        );
        let only_user = ProxyRequest {
            username: Some(" bob ".into()),
            ..url_only("http://proxy:1")
        };
        store.set_proxy(&only_user).unwrap();
        assert_eq!(
            stored(&secrets, PROXY_USERNAME_NAME).as_deref(),
            Some("bob")
        );
        assert_eq!(
            stored(&secrets, PROXY_PASSWORD_NAME).as_deref(),
            Some("two")
        );
        // Saving the URL again (empty credential fields) changes nothing and needs no restart for it.
        let (_, change) = store.set_proxy(&url_only("http://proxy:1")).unwrap();
        assert_eq!(change, CredentialChange::Unchanged);
        let empty_user = ProxyRequest {
            username: Some(String::new()),
            ..url_only("http://proxy:1")
        };
        let (view, change) = store.set_proxy(&empty_user).unwrap();
        assert_eq!(change, CredentialChange::Unchanged);
        assert_eq!(view.proxy_username.as_deref(), Some("bob"));
    }

    #[test]
    fn invalid_credentials_are_refused_without_echoing_them() {
        let secrets = memory();
        let store = SettingsStore::open(None, secrets.clone());
        let cases = [
            with_credentials("http://p:1", "", "pw"), // empty user with a password
            with_credentials("http://p:1", "bad\nname", "pw"), // control character
            with_credentials("http://p:1", "alice", "bad\u{7}pw"), // control character
            with_credentials("http://p:1", &"u".repeat(257), "pw"), // too long
            with_credentials("http://p:1", "alice", &"p".repeat(513)), // too long
            with_credentials("http://p:1", "alice", ""), // empty password
            ProxyRequest {
                password: Some("pw".into()),
                ..url_only("http://p:1")
            }, // password with no user name at all
            ProxyRequest {
                username: Some("alice".into()),
                ..url_only("http://p:1")
            }, // user name with no password at all
            with_credentials("", "alice", "pw"),      // no explicit proxy to authenticate against
        ];
        for request in cases {
            let err = store.set_proxy(&request).unwrap_err();
            assert!(matches!(err.code, ErrorCode::BadRequest), "{request:?}");
            assert!(!err.message.contains("alice") && !err.message.contains("pw\u{7}"));
        }
        assert!(stored(&secrets, PROXY_USERNAME_NAME).is_none());
        assert!(store.view().proxy.is_none());
    }

    #[test]
    fn credentials_can_be_removed_and_follow_the_proxy() {
        let secrets = memory();
        let store = SettingsStore::open(None, secrets.clone());
        store
            .set_proxy(&with_credentials("http://proxy:1", "alice", "one"))
            .unwrap();
        let clear = ProxyRequest {
            clear_credentials: true,
            ..url_only("http://proxy:1")
        };
        let (view, change) = store.set_proxy(&clear).unwrap();
        assert_eq!(change, CredentialChange::Removed);
        assert!(!view.proxy_credentials && view.proxy_username.is_none());
        assert!(stored(&secrets, PROXY_USERNAME_NAME).is_none());
        assert!(stored(&secrets, PROXY_PASSWORD_NAME).is_none());
        // Going back to the system proxy removes stored credentials too.
        store
            .set_proxy(&with_credentials("http://proxy:1", "alice", "one"))
            .unwrap();
        let none = ProxyRequest {
            proxy: None,
            ..url_only("")
        };
        let (view, change) = store.set_proxy(&none).unwrap();
        assert_eq!(change, CredentialChange::Removed);
        assert!(view.proxy.is_none() && !view.proxy_credentials);
        assert!(stored(&secrets, PROXY_PASSWORD_NAME).is_none());
    }

    #[test]
    fn changing_only_the_credentials_asks_for_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = memory();
        let store = SettingsStore::open(Some(dir.path()), secrets.clone());
        store.set_proxy(&url_only("http://proxy:1")).unwrap();
        let running = SettingsStore::open(Some(dir.path()), secrets.clone());
        assert!(!running.view().restart_required);
        let (view, _) = running
            .set_proxy(&with_credentials("http://proxy:1", "alice", "one"))
            .unwrap();
        assert!(view.restart_required);
        // Setting them back to what the running agent has (none) needs no restart.
        let clear = ProxyRequest {
            clear_credentials: true,
            ..url_only("http://proxy:1")
        };
        assert!(!running.set_proxy(&clear).unwrap().0.restart_required);
    }

    #[test]
    fn no_credentials_in_the_store_is_fine_and_a_store_failure_never_loses_the_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing stored: the agent starts without credentials.
        assert!(load_proxy_auth(&MemorySecretStore::new()).is_none());
        let secrets = memory();
        secrets
            .set(PROXY_USERNAME_NAME, &Secret::new("alice"))
            .unwrap();
        assert!(
            load_proxy_auth(secrets.as_ref()).is_none(),
            "half an entry is no entry"
        );

        struct FailingStore(MemorySecretStore);
        impl SecretStore for FailingStore {
            fn get(&self, name: &str) -> Result<Option<Secret>, SecretError> {
                self.0.get(name)
            }
            fn set(&self, name: &str, value: &Secret) -> Result<(), SecretError> {
                if name == PROXY_PASSWORD_NAME && value.expose() == "boom" {
                    return Err(SecretError::Store("denied".into()));
                }
                self.0.set(name, value)
            }
            fn delete(&self, name: &str) -> Result<(), SecretError> {
                self.0.delete(name)
            }
        }
        let failing = Arc::new(FailingStore(MemorySecretStore::new()));
        let store = SettingsStore::open(Some(dir.path()), failing.clone());
        store
            .set_proxy(&with_credentials("http://proxy:1", "alice", "good"))
            .unwrap();
        let err = store
            .set_proxy(&with_credentials("http://proxy:1", "bob", "boom"))
            .unwrap_err();
        assert!(matches!(err.code, ErrorCode::Internal));
        assert!(!err.message.contains("boom"));
        let auth = load_proxy_auth(failing.as_ref()).unwrap();
        assert_eq!((auth.username(), auth.password()), ("alice", "good"));
        assert_eq!(store.view().proxy_username.as_deref(), Some("alice"));
    }

    #[test]
    fn stored_credentials_are_only_used_with_a_saved_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = memory();
        secrets
            .set(PROXY_USERNAME_NAME, &Secret::new("alice"))
            .unwrap();
        secrets
            .set(PROXY_PASSWORD_NAME, &Secret::new("one"))
            .unwrap();
        assert!(saved_proxy_auth(Some(dir.path()), secrets.as_ref()).is_none());
        let store = SettingsStore::open(Some(dir.path()), secrets.clone());
        store.set_proxy(&url_only("http://proxy:1")).unwrap();
        assert!(saved_proxy_auth(Some(dir.path()), secrets.as_ref()).is_some());
    }

    #[test]
    fn an_unreadable_file_means_no_proxy() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), "{ not json").unwrap();
        assert!(saved_proxy(Some(dir.path())).is_none());
    }

    #[test]
    fn the_capture_starts_with_the_agent_unless_the_user_switched_it_off() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing saved: on.
        assert!(saved_capture_on_start(Some(dir.path())));
        assert!(saved_capture_on_start(None));
        let store = SettingsStore::open(Some(dir.path()), memory());
        assert!(store.view().capture_on_start);
        let view = store.set_capture_on_start(false).unwrap();
        assert!(!view.capture_on_start);
        assert!(
            !saved_capture_on_start(Some(dir.path())),
            "it survives a restart"
        );
        // A restarted store shows it off, and the proxy setting does not undo it.
        let restarted = SettingsStore::open(Some(dir.path()), memory());
        assert!(!restarted.view().capture_on_start);
        restarted.set_proxy(&url_only("http://proxy:3128")).unwrap();
        assert!(!saved_capture_on_start(Some(dir.path())));
        let on = restarted.set_capture_on_start(true).unwrap();
        assert!(on.capture_on_start);
        assert!(saved_capture_on_start(Some(dir.path())));
        // The proxy survived the capture switch too.
        assert_eq!(
            saved_proxy(Some(dir.path())).as_deref(),
            Some("http://proxy:3128")
        );
    }

    #[test]
    fn an_old_settings_file_without_the_field_keeps_capturing() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), r#"{"proxy":"http://p:1"}"#).unwrap();
        assert!(saved_capture_on_start(Some(dir.path())));
        assert!(
            SettingsStore::open(Some(dir.path()), memory())
                .view()
                .capture_on_start
        );
    }
}
