// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Blocklist source definitions and the download step. Definitions only: no list is bundled or committed; lists
//! are fetched at runtime, and only when the user enabled them.

use super::parse::ParseError;
use super::verify::{Verifier, VerifyError};
use crate::{FetchError, FetchRequest, Fetcher};

/// Public repository that publishes the shared list and `nodes.json`.
pub const XEROHOST_REPO: &str = "XeroHost/packetward-blocklist";
/// Raw GitHub URL of the signed list. The branch name (`main`) is an assumption until the repository exists.
pub const XEROHOST_LIST_URL: &str =
    "https://raw.githubusercontent.com/XeroHost/packetward-blocklist/main/blocklist.txt";
/// Raw GitHub URL of its minisign signature.
pub const XEROHOST_SIGNATURE_URL: &str =
    "https://raw.githubusercontent.com/XeroHost/packetward-blocklist/main/blocklist.txt.minisig";
/// A `.minisig` file is a few hundred bytes.
pub const SIGNATURE_MAX_BYTES: usize = 4 * 1024;

/// Stable identifier of the XeroHost list (also used in firewall rule names, `PW-List-<id>-NNN`).
pub const XEROHOST_LIST_ID: &str = "xerohost";

/// Where a list comes from and how it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Must verify against the pinned minisign key; fails closed.
    Signed,
    /// Plain public list the user opted into.
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSource {
    /// Lowercase `[a-z0-9-]`, stable, safe inside a firewall rule name.
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// One URL per file. Bodies are concatenated (Spamhaus publishes IPv4 and IPv6 separately).
    pub urls: &'static [&'static str],
    /// `Some` for [`ListKind::Signed`].
    pub signature_url: Option<&'static str>,
    pub kind: ListKind,
    /// Off until the user turns it on (the XeroHost list needs the first-run confirmation).
    pub default_enabled: bool,
    pub default_refresh_secs: u64,
}

impl ListSource {
    pub fn is_signed(&self) -> bool {
        self.kind == ListKind::Signed
    }
}

/// The lists PacketWard knows about. All are disabled by default.
pub fn builtin_sources() -> Vec<ListSource> {
    vec![
        ListSource {
            id: XEROHOST_LIST_ID,
            name: "XeroHost shared blocklist",
            description: "Maintained by XeroHost, signature-verified against the key pinned in the app.",
            urls: &[XEROHOST_LIST_URL],
            signature_url: Some(XEROHOST_SIGNATURE_URL),
            kind: ListKind::Signed,
            default_enabled: false,
            default_refresh_secs: 6 * 3600,
        },
        ListSource {
            id: "spamhaus-drop",
            name: "Spamhaus DROP",
            description: "Hijacked and criminal-operated netblocks. Check Spamhaus's terms of use for your case.",
            // The legacy text files. Spamhaus is moving to JSON; unverified until tested against the live service.
            urls: &[
                "https://www.spamhaus.org/drop/drop.txt",
                "https://www.spamhaus.org/drop/dropv6.txt",
            ],
            signature_url: None,
            kind: ListKind::Public,
            default_enabled: false,
            default_refresh_secs: 24 * 3600,
        },
        ListSource {
            id: "firehol-level1",
            name: "FireHOL level 1",
            description: "Aggregated attack and abuse sources with a very low false-positive rate.",
            urls: &[
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            ],
            signature_url: None,
            kind: ListKind::Public,
            default_enabled: false,
            default_refresh_secs: 24 * 3600,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlocklistError {
    #[error("unknown blocklist {0:?}")]
    UnknownList(String),
    #[error("the blocklist is disabled")]
    Disabled,
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("download failed: {0}")]
    Fetch(#[from] FetchError),
    #[error("the server answered HTTP {0}")]
    HttpStatus(u16),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

async fn get_ok<F: Fetcher>(
    fetcher: &F,
    url: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, BlocklistError> {
    let response = fetcher.fetch(FetchRequest::get(url, max_bytes)).await?;
    if !response.is_success() {
        return Err(BlocklistError::HttpStatus(response.status));
    }
    Ok(response.body)
}

/// Download the raw content of `source`. For a signed list the pinned key is checked *before* any request, the
/// signature is fetched and verified over the exact bytes of the file, and only verified bytes are returned. The
/// size cap applies to the combined body of a multi-file public list.
pub async fn download<F: Fetcher>(
    fetcher: &F,
    source: &ListSource,
    verifier: &Verifier,
    max_bytes: usize,
) -> Result<Vec<u8>, BlocklistError> {
    if let (ListKind::Signed, Some(signature_url), Some(url)) =
        (source.kind, source.signature_url, source.urls.first())
    {
        // Fail closed without touching the network when there is nothing to verify against.
        verifier.check_ready()?;
        let content = get_ok(fetcher, url, max_bytes).await?;
        let signature = match get_ok(fetcher, signature_url, SIGNATURE_MAX_BYTES).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            // An absent signature file is a verification failure, not a transport problem.
            Err(BlocklistError::HttpStatus(404)) => String::new(),
            Err(other) => return Err(other),
        };
        verifier.verify(&content, &signature)?;
        return Ok(content);
    }
    if source.is_signed() {
        // A signed source without a signature URL is a definition error: never treat it as unsigned.
        return Err(VerifyError::MissingSignature.into());
    }
    let mut content = Vec::new();
    for url in source.urls {
        let remaining = max_bytes.saturating_sub(content.len());
        let body = get_ok(fetcher, url, remaining).await?;
        content.extend_from_slice(&body);
        content.push(b'\n');
        if content.len() > max_bytes {
            return Err(FetchError::TooLarge { limit: max_bytes }.into());
        }
    }
    Ok(content)
}
