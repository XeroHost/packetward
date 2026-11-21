// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Minisign verification of the shared blocklist against the pinned public key. Fails closed.

use minisign_verify::{Error as MinisignError, PublicKey, Signature};

use super::pinned_key::PINNED_PUBLIC_KEY;

/// Why a signed list was rejected. Every cause is distinct so the UI can say what is wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// No public key is compiled into this build: the XeroHost list stays disabled.
    #[error("no pinned key configured: the XeroHost blocklist is disabled")]
    NoPinnedKey,
    /// The configured key is not valid minisign base64. A build problem, never data from the network.
    #[error("the pinned public key is malformed")]
    InvalidPinnedKey,
    #[error("the signature file is missing or empty")]
    MissingSignature,
    #[error("the signature file is malformed")]
    MalformedSignature,
    /// Signed by a different key than the pinned one.
    #[error("the list is signed with a different key than the pinned one")]
    WrongKey,
    /// Correct key id but the signature does not match: the list (or the signature) was altered.
    #[error("the signature does not match the list: it was altered or corrupted")]
    SignatureMismatch,
    /// Valid format but not a prehashed minisign signature.
    #[error("unsupported signature algorithm (legacy signatures are refused)")]
    UnsupportedAlgorithm,
}

/// Verifies list content against one public key.
#[derive(Debug, Clone)]
pub struct Verifier {
    key: Option<String>,
}

impl Verifier {
    /// The production verifier: the key compiled into the app (`PINNED_PUBLIC_KEY`).
    pub fn pinned() -> Self {
        Self {
            key: PINNED_PUBLIC_KEY.map(str::to_owned),
        }
    }

    /// A verifier for an explicit base64 key. Test-only (`testing` feature): production code can only ever verify
    /// against the pinned key, so the fail-closed rule holds by construction.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_key(public_key_base64: impl Into<String>) -> Self {
        Self {
            key: Some(public_key_base64.into()),
        }
    }

    /// A verifier without a key: everything is rejected with [`VerifyError::NoPinnedKey`].
    pub fn without_key() -> Self {
        Self { key: None }
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// `Ok(())` when the key is configured and well-formed, otherwise the reason the signed list cannot be used.
    /// Called before any network request, so a build without a key never even downloads the list.
    pub fn check_ready(&self) -> Result<(), VerifyError> {
        self.public_key().map(|_| ())
    }

    fn public_key(&self) -> Result<PublicKey, VerifyError> {
        let key = self.key.as_deref().ok_or(VerifyError::NoPinnedKey)?;
        PublicKey::from_base64(key.trim()).map_err(|_| VerifyError::InvalidPinnedKey)
    }

    /// Verify `content` against the text of its `.minisig` file.
    pub fn verify(&self, content: &[u8], signature_text: &str) -> Result<(), VerifyError> {
        let key = self.public_key()?;
        if signature_text.trim().is_empty() {
            return Err(VerifyError::MissingSignature);
        }
        let signature =
            Signature::decode(signature_text).map_err(|_| VerifyError::MalformedSignature)?;
        // `allow_legacy = false`: only the prehashed mode that the `minisign` tool produces by default.
        key.verify(content, &signature, false).map_err(|e| match e {
            MinisignError::UnexpectedKeyId => VerifyError::WrongKey,
            MinisignError::UnexpectedAlgorithm | MinisignError::UnsupportedAlgorithm => {
                VerifyError::UnsupportedAlgorithm
            }
            MinisignError::InvalidEncoding => VerifyError::MalformedSignature,
            _ => VerifyError::SignatureMismatch,
        })
    }
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! Throwaway keys for tests. Generated at test time, never written to disk, never a real key.

    use std::io::Cursor;

    pub struct TestKey {
        pub pair: minisign::KeyPair,
    }

    impl TestKey {
        pub fn generate() -> Self {
            Self {
                pair: minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
            }
        }

        pub fn public_base64(&self) -> String {
            self.pair.pk.to_base64()
        }

        pub fn sign(&self, content: &[u8]) -> String {
            minisign::sign(
                Some(&self.pair.pk),
                &self.pair.sk,
                Cursor::new(content),
                Some("timestamp:1"),
                Some("test signature"),
            )
            .unwrap()
            .into_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::TestKey;
    use super::*;

    const LIST: &[u8] = b"# test list\n203.0.113.0/24\n45.33.32.0/24\n";

    #[test]
    fn a_valid_signature_verifies() {
        let key = TestKey::generate();
        let sig = key.sign(LIST);
        let verifier = Verifier::with_key(key.public_base64());
        assert_eq!(verifier.verify(LIST, &sig), Ok(()));
    }

    #[test]
    fn tampered_content_is_rejected() {
        let key = TestKey::generate();
        let sig = key.sign(LIST);
        let verifier = Verifier::with_key(key.public_base64());
        let mut tampered = LIST.to_vec();
        tampered.extend_from_slice(b"1.2.3.4\n");
        assert_eq!(
            verifier.verify(&tampered, &sig),
            Err(VerifyError::SignatureMismatch)
        );
        // A single flipped byte too.
        let mut flipped = LIST.to_vec();
        flipped[12] ^= 1;
        assert_eq!(
            verifier.verify(&flipped, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let key = TestKey::generate();
        let sig = key.sign(LIST);
        let verifier = Verifier::with_key(key.public_base64());
        // Alter the trusted comment: the global signature no longer matches.
        let altered = sig.replace("timestamp:1", "timestamp:2");
        assert_ne!(altered, sig);
        assert_eq!(
            verifier.verify(LIST, &altered),
            Err(VerifyError::SignatureMismatch)
        );
        // Truncated / garbage signature text.
        assert_eq!(
            verifier.verify(LIST, "untrusted comment: x\nnot-base64!!\n"),
            Err(VerifyError::MalformedSignature)
        );
    }

    #[test]
    fn a_signature_by_another_key_is_rejected_as_wrong_key() {
        let signer = TestKey::generate();
        let pinned = TestKey::generate();
        let sig = signer.sign(LIST);
        let verifier = Verifier::with_key(pinned.public_base64());
        assert_eq!(verifier.verify(LIST, &sig), Err(VerifyError::WrongKey));
    }

    #[test]
    fn a_missing_signature_is_rejected() {
        let key = TestKey::generate();
        let verifier = Verifier::with_key(key.public_base64());
        assert_eq!(
            verifier.verify(LIST, ""),
            Err(VerifyError::MissingSignature)
        );
        assert_eq!(
            verifier.verify(LIST, "  \n\r\n"),
            Err(VerifyError::MissingSignature)
        );
    }

    #[test]
    fn without_a_pinned_key_everything_fails_closed() {
        let key = TestKey::generate();
        let sig = key.sign(LIST);
        let verifier = Verifier::without_key();
        assert!(!verifier.has_key());
        assert_eq!(verifier.verify(LIST, &sig), Err(VerifyError::NoPinnedKey));
        assert_eq!(verifier.check_ready(), Err(VerifyError::NoPinnedKey));
        assert!(VerifyError::NoPinnedKey
            .to_string()
            .contains("no pinned key configured"));
    }

    #[test]
    fn the_shipped_pinned_key_is_consistent() {
        // While the placeholder is in place (docs/RELEASE-KEYS.md, step 2) the build must fail closed; once the
        // real key is pinned it must at least be well-formed.
        let verifier = Verifier::pinned();
        assert_eq!(verifier.has_key(), PINNED_PUBLIC_KEY.is_some());
        match PINNED_PUBLIC_KEY {
            None => {
                assert_eq!(verifier.check_ready(), Err(VerifyError::NoPinnedKey));
                assert_eq!(
                    verifier.verify(LIST, "anything"),
                    Err(VerifyError::NoPinnedKey)
                );
            }
            Some(_) => assert_eq!(verifier.check_ready(), Ok(())),
        }
    }

    #[test]
    fn a_malformed_pinned_key_is_reported_as_such() {
        let verifier = Verifier::with_key("RWnot-a-key");
        assert_eq!(verifier.check_ready(), Err(VerifyError::InvalidPinnedKey));
    }
}
