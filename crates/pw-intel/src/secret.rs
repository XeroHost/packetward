// SPDX-License-Identifier: GPL-3.0-or-later
//! Secret handling. Secrets (the AbuseIPDB key, the proxy credentials) live in the OS credential store, never in plain config, and
//! never reach a log line: [`Secret`] redacts itself in `Debug` and has no `Display` or `Serialize`.

use std::collections::HashMap;
use std::sync::Mutex;

/// A secret value. `Debug` prints `Secret(<redacted>)`; reading it requires the explicit [`Secret::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw value. Call only where it is placed into a request header; never log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Service name used for every credential PacketWard stores.
pub const SECRET_SERVICE: &str = "PacketWard";
/// Credential name of the AbuseIPDB API key.
pub const ABUSEIPDB_KEY_NAME: &str = "abuseipdb-api-key";
/// Credential name of the proxy user name (the proxy URL itself never carries credentials).
pub const PROXY_USERNAME_NAME: &str = "proxy-username";
/// Credential name of the proxy password.
pub const PROXY_PASSWORD_NAME: &str = "proxy-password";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The credential store failed. The message comes from the store and never contains the secret.
    #[error("credential store error: {0}")]
    Store(String),
}

/// Where secrets are kept. The real implementation is `KeyringSecretStore` (Windows Credential Manager, only
/// compiled on Windows); tests and tools use [`MemorySecretStore`].
pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Secret>, SecretError>;
    fn set(&self, name: &str, value: &Secret) -> Result<(), SecretError>;
    fn delete(&self, name: &str) -> Result<(), SecretError>;
}

/// In-memory store (tests, dev tools). Nothing is persisted.
#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<HashMap<String, Secret>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Secret>> {
        self.values.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl std::fmt::Debug for MemorySecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemorySecretStore")
            .field("entries", &self.lock().len())
            .finish()
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&self, name: &str) -> Result<Option<Secret>, SecretError> {
        Ok(self.lock().get(name).cloned())
    }

    fn set(&self, name: &str, value: &Secret) -> Result<(), SecretError> {
        self.lock().insert(name.to_owned(), value.clone());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        self.lock().remove(name);
        Ok(())
    }
}

/// Windows Credential Manager through the `keyring` crate.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyringSecretStore;

#[cfg(windows)]
impl KeyringSecretStore {
    fn entry(name: &str) -> Result<keyring::Entry, SecretError> {
        keyring::Entry::new(SECRET_SERVICE, name).map_err(|e| SecretError::Store(e.to_string()))
    }
}

#[cfg(windows)]
impl SecretStore for KeyringSecretStore {
    fn get(&self, name: &str) -> Result<Option<Secret>, SecretError> {
        match Self::entry(name)?.get_password() {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(SecretError::Store(e.to_string())),
        }
    }

    fn set(&self, name: &str, value: &Secret) -> Result<(), SecretError> {
        Self::entry(name)?
            .set_password(value.expose())
            .map_err(|e| SecretError::Store(e.to_string()))
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Store(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_value() {
        let secret = Secret::new("super-secret-value");
        assert!(!format!("{secret:?}").contains("super-secret"));
        assert!(!format!("{:?}", Some(&secret)).contains("super-secret"));
    }

    /// Touches the real Windows Credential Manager (creates and deletes one throwaway credential), so it is
    /// opt-in: `cargo test -p pw-intel -- --ignored keyring`.
    #[cfg(windows)]
    #[test]
    #[ignore = "uses the real Windows Credential Manager"]
    fn keyring_round_trip() {
        let store = KeyringSecretStore;
        let name = format!("pw-intel-test-{}", std::process::id());
        assert!(store.get(&name).unwrap().is_none());
        store.set(&name, &Secret::new("test-value")).unwrap();
        assert_eq!(store.get(&name).unwrap().unwrap().expose(), "test-value");
        store.delete(&name).unwrap();
        assert!(store.get(&name).unwrap().is_none());
        store.delete(&name).unwrap(); // deleting a missing entry is fine
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemorySecretStore::new();
        assert!(store.get("k").unwrap().is_none());
        store.set("k", &Secret::new("v")).unwrap();
        assert_eq!(store.get("k").unwrap().unwrap().expose(), "v");
        store.delete("k").unwrap();
        assert!(store.get("k").unwrap().is_none());
    }
}
