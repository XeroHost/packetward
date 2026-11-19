// SPDX-License-Identifier: GPL-3.0-or-later
//! Where streamed results go: a bounded channel or a plain callback.

use std::future::Future;

use tokio::sync::mpsc;

/// Receiver of streamed items (ping replies, MTR cycle snapshots).
///
/// `deliver` returns `false` when the consumer is gone; the running diagnostic treats that as a
/// cancellation. A slow consumer applies back-pressure on the diagnostic (it never grows a queue).
pub trait Sink<T: Send>: Send {
    /// Hand one item over. `false` means "stop, nobody is listening".
    fn deliver(&mut self, item: T) -> impl Future<Output = bool> + Send;
}

impl<T: Send> Sink<T> for mpsc::Sender<T> {
    async fn deliver(&mut self, item: T) -> bool {
        self.send(item).await.is_ok()
    }
}

/// Adapter turning a closure into a [`Sink`].
#[derive(Debug)]
pub struct FnSink<F>(pub F);

impl<T: Send, F: FnMut(T) + Send> Sink<T> for FnSink<F> {
    async fn deliver(&mut self, item: T) -> bool {
        (self.0)(item);
        true
    }
}

/// A sink that drops everything (the caller only wants the final result).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl<T: Send> Sink<T> for NullSink {
    async fn deliver(&mut self, _item: T) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn channel_sink_reports_closed_receiver() {
        let (mut tx, mut rx) = mpsc::channel::<u8>(1);
        assert!(tx.deliver(1).await);
        assert_eq!(rx.recv().await, Some(1));
        drop(rx);
        assert!(!tx.deliver(2).await);
    }

    #[tokio::test]
    async fn fn_sink_calls_closure() {
        let mut seen = Vec::new();
        {
            let mut sink = FnSink(|x: u8| seen.push(x));
            assert!(sink.deliver(7).await);
        }
        assert_eq!(seen, vec![7]);
    }
}
