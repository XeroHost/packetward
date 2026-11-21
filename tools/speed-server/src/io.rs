// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! An I/O wrapper that closes a connection after `idle` without any read or write progress.
//!
//! It covers idle keep-alive connections, slow-loris clients and readers/writers that stall mid-transfer,
//! while a healthy 50 GB download never trips it (every successful write is progress).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// See the module documentation.
pub struct IdleIo<T> {
    inner: T,
    idle: Duration,
    sleep: Pin<Box<Sleep>>,
    last_activity: Instant,
}

impl<T> IdleIo<T> {
    /// Wrap `inner`.
    pub fn new(inner: T, idle: Duration) -> Self {
        let now = Instant::now();
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep_until(now + idle)),
            last_activity: now,
        }
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Called when the inner I/O returned `Pending`: arm/check the idle timer.
    fn pending<R>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<R>> {
        if self.sleep.as_mut().poll(cx).is_ready() {
            let deadline = self.last_activity + self.idle;
            if Instant::now() >= deadline {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection idle timeout",
                )));
            }
            // There was activity since the timer was armed: sleep for the remainder.
            self.sleep.as_mut().reset(deadline);
            // Register the waker with the re-armed timer; it cannot be ready yet.
            let _ = self.sleep.as_mut().poll(cx);
        }
        Poll::Pending
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                this.touch();
                Poll::Ready(r)
            }
            Poll::Pending => this.pending(cx),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(r) => {
                this.touch();
                Poll::Ready(r)
            }
            Poll::Pending => this.pending(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => this.pending(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(r) => {
                this.touch();
                Poll::Ready(r)
            }
            Poll::Pending => this.pending(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
