// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Credentials for an authenticating proxy. They are never part of the proxy URL and never reach a log:
//! `Debug` prints nothing but a marker, and there is no `Display` or `Serialize`.

/// Longest accepted user name.
pub const MAX_PROXY_USERNAME_LEN: usize = 256;
/// Longest accepted password.
pub const MAX_PROXY_PASSWORD_LEN: usize = 512;

/// A user name and password for basic authentication against a proxy.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    username: String,
    password: String,
}

impl ProxyAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// The raw password. Call only where it is handed to the HTTP client; never log the result.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyAuth(<redacted>)")
    }
}

/// Checks a user name: 1..=256 bytes, no control characters. The message never repeats the value.
pub fn validate_proxy_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() {
        return Err("the proxy user name is empty");
    }
    if username.len() > MAX_PROXY_USERNAME_LEN {
        return Err("the proxy user name is too long");
    }
    if username.chars().any(char::is_control) {
        return Err("the proxy user name contains control characters");
    }
    Ok(())
}

/// Checks a password: 1..=512 bytes, no control characters. The message never repeats the value.
pub fn validate_proxy_password(password: &str) -> Result<(), &'static str> {
    if password.is_empty() {
        return Err("the proxy password is empty");
    }
    if password.len() > MAX_PROXY_PASSWORD_LEN {
        return Err("the proxy password is too long");
    }
    if password.chars().any(char::is_control) {
        return Err("the proxy password contains control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_credentials() {
        let auth = ProxyAuth::new("alice", "hunter2");
        let text = format!("{auth:?} {:?}", Some(&auth));
        assert!(!text.contains("alice") && !text.contains("hunter2"));
    }

    #[test]
    fn user_names_and_passwords_are_validated() {
        assert!(validate_proxy_username("DOMAIN\\alice").is_ok());
        assert!(validate_proxy_username("").is_err());
        assert!(validate_proxy_username("a\nb").is_err());
        assert!(validate_proxy_username(&"u".repeat(257)).is_err());
        assert!(validate_proxy_username(&"u".repeat(256)).is_ok());
        assert!(validate_proxy_password("p@ss w0rd:/?#").is_ok());
        assert!(validate_proxy_password("").is_err());
        assert!(validate_proxy_password("a\u{0}b").is_err());
        assert!(validate_proxy_password(&"p".repeat(513)).is_err());
        assert!(validate_proxy_password(&"p".repeat(512)).is_ok());
    }

    #[test]
    fn validation_messages_do_not_echo_the_value() {
        let err = validate_proxy_password("secret\n").unwrap_err();
        assert!(!err.contains("secret"));
    }
}
