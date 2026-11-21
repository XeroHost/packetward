// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! A tiny cooperative cancellation token (no `tokio_util` dependency).

use std::sync::Arc;

use tokio::sync::watch;

/// Cloneable cancellation flag. All clones share the same state; [`CancelToken::cancel`] on any
/// clone wakes every waiter in [`CancelToken::cancelled`].
#[derive(Debug, Clone)]
pub struct CancelToken {
    // Each clone keeps the sender alive, so a receiver never observes a closed channel.
    tx: Arc<watch::Sender<bool>>,
    rx: watch::Receiver<bool>,
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    /// A fresh, not-yet-cancelled token.
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            tx: Arc::new(tx),
            rx,
        }
    }

    /// Request cancellation. Idempotent.
    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    /// Whether [`cancel`](Self::cancel) was called on this token or any clone of it.
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Completes once the token is cancelled (immediately if it already is).
    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        // An Err means the sender is gone, which cannot happen while `self` holds it; treat it as
        // cancelled anyway rather than waiting forever.
        let _ = rx.wait_for(|cancelled| *cancelled).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_resolves_after_cancel_on_any_clone() {
        let token = CancelToken::new();
        let other = token.clone();
        assert!(!token.is_cancelled());
        let waiter = tokio::spawn(async move { other.cancelled().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        token.cancel();
        assert!(tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .is_ok());
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn already_cancelled_returns_immediately() {
        let token = CancelToken::new();
        token.cancel();
        token.cancel();
        token.cancelled().await;
    }
}
