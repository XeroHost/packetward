// SPDX-License-Identifier: GPL-3.0-or-later
//! Stand-in for the Win32 ICMP backend on other platforms, so the engine compiles everywhere.

use crate::echo::{EchoReply, EchoRequest, Pinger};
use crate::error::DiagError;

/// A [`Pinger`] that always fails with [`DiagError::Unsupported`].
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedPinger;

impl Pinger for UnsupportedPinger {
    async fn echo(&self, _request: &EchoRequest) -> Result<EchoReply, DiagError> {
        Err(DiagError::Unsupported("ICMP echo"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn always_unsupported() {
        let req = EchoRequest {
            target: "127.0.0.1".parse().unwrap(),
            ttl: 64,
            payload_size: 32,
            timeout: std::time::Duration::from_secs(1),
        };
        assert!(matches!(
            UnsupportedPinger.echo(&req).await,
            Err(DiagError::Unsupported(_))
        ));
    }
}
