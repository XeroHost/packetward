// SPDX-License-Identifier: GPL-3.0-or-later
//! Agent settings that survive restarts (`settings.json` in the agent data folder). Today: the proxy
//! used by every outbound HTTP call (update check, speed test, GeoIP and blocklist downloads,
//! AbuseIPDB). It is read once when the agent starts, so a change needs a service restart.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pw_proto::{AgentSettingsView, ErrorCode, ErrorPayload};
use serde::{Deserialize, Serialize};

const FILE: &str = "settings.json";
const MAX_PROXY_LEN: usize = 256;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    proxy: Option<String>,
}

pub struct SettingsStore {
    path: Option<PathBuf>,
    saved: Mutex<Saved>,
    /// The proxy the running agent was started with.
    applied_proxy: Option<String>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The proxy saved in `dir`, if any (read before the HTTP clients are built).
pub fn saved_proxy(dir: Option<&Path>) -> Option<String> {
    let text = fs::read_to_string(dir?.join(FILE)).ok()?;
    let saved: Saved = serde_json::from_str(&text).ok()?;
    saved.proxy.filter(|p| validate_proxy(p).is_ok())
}

/// Accepts `http://`, `https://`, `socks5://` and `socks5h://` URLs with a host and no credentials
/// (secrets never go to a plain settings file).
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
            "proxy credentials are not supported: use a proxy that does not ask for them"
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
    pub fn open(dir: Option<&Path>) -> Self {
        let applied_proxy = saved_proxy(dir);
        Self {
            path: dir.map(|d| d.join(FILE)),
            saved: Mutex::new(Saved {
                proxy: applied_proxy.clone(),
            }),
            applied_proxy,
        }
    }

    pub fn view(&self) -> AgentSettingsView {
        let proxy = lock(&self.saved).proxy.clone();
        AgentSettingsView {
            restart_required: proxy != self.applied_proxy,
            proxy,
            applied_proxy: self.applied_proxy.clone(),
        }
    }

    pub fn set_proxy(&self, proxy: Option<String>) -> Result<AgentSettingsView, ErrorPayload> {
        let proxy = proxy.map(|p| p.trim().to_owned()).filter(|p| !p.is_empty());
        if let Some(value) = &proxy {
            validate_proxy(value).map_err(|m| ErrorPayload::new(ErrorCode::BadRequest, m))?;
        }
        let mut saved = lock(&self.saved);
        saved.proxy = proxy;
        if let Some(path) = &self.path {
            let write = || -> std::io::Result<()> {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let tmp = path.with_extension("json.tmp");
                fs::write(
                    &tmp,
                    serde_json::to_vec_pretty(&*saved).map_err(std::io::Error::other)?,
                )?;
                fs::rename(tmp, path)
            };
            write().map_err(|e| {
                ErrorPayload::new(ErrorCode::Internal, format!("could not save settings: {e}"))
            })?;
        }
        drop(saved);
        Ok(self.view())
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

    #[test]
    fn a_change_is_saved_and_needs_a_restart_until_the_agent_starts_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = SettingsStore::open(Some(dir.path()));
        assert!(!store.view().restart_required);
        let view = store.set_proxy(Some(" http://proxy:3128 ".into())).unwrap();
        assert_eq!(view.proxy.as_deref(), Some("http://proxy:3128"));
        assert!(view.restart_required && view.applied_proxy.is_none());
        // The next start reads it and has nothing left to apply.
        assert_eq!(
            saved_proxy(Some(dir.path())).as_deref(),
            Some("http://proxy:3128")
        );
        let restarted = SettingsStore::open(Some(dir.path()));
        assert!(!restarted.view().restart_required);
        // Going back to the system proxy is a change again.
        assert!(restarted.set_proxy(None).unwrap().restart_required);
        assert!(saved_proxy(Some(dir.path())).is_none());
    }

    #[test]
    fn a_bad_proxy_is_refused_and_nothing_changes() {
        let store = SettingsStore::open(None);
        let err = store
            .set_proxy(Some("http://user:pw@proxy:1".into()))
            .unwrap_err();
        assert!(matches!(err.code, ErrorCode::BadRequest));
        assert!(store.view().proxy.is_none());
    }

    #[test]
    fn an_unreadable_file_means_no_proxy() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), "{ not json").unwrap();
        assert!(saved_proxy(Some(dir.path())).is_none());
    }
}
