// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! In-memory transport for tests. Never used in production.

use std::io;

use tokio::io::{duplex, DuplexStream};
use tokio::sync::mpsc;

use crate::server::Listener;

const BUFFER: usize = 64 * 1024;

pub struct MemoryListener {
    incoming: mpsc::Receiver<DuplexStream>,
}

#[derive(Clone)]
pub struct MemoryConnector {
    outgoing: mpsc::Sender<DuplexStream>,
}

/// A connected listener/connector pair.
pub fn memory_pair() -> (MemoryListener, MemoryConnector) {
    let (tx, rx) = mpsc::channel(16);
    (
        MemoryListener { incoming: rx },
        MemoryConnector { outgoing: tx },
    )
}

impl MemoryConnector {
    /// Opens a new connection to the listener.
    pub async fn connect(&self) -> io::Result<DuplexStream> {
        let (client, server) = duplex(BUFFER);
        self.outgoing
            .send(server)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "listener is gone"))?;
        Ok(client)
    }
}

impl Listener for MemoryListener {
    type Stream = DuplexStream;

    async fn accept(&mut self) -> io::Result<DuplexStream> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "all connectors dropped"))
    }
}
