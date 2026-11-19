// SPDX-License-Identifier: GPL-3.0-or-later
//! In-memory [`NetStat`] for tests of the engine and anything built on it.

use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

use pw_proto::RdpSession;

use crate::{ConnectionTable, InterfaceSample, NetStat};

#[derive(Default)]
struct State {
    table: ConnectionTable,
    interfaces: Vec<InterfaceSample>,
    rdp: Vec<RdpSession>,
    fail_connections: bool,
}

/// Scripted network state: set what the "OS" reports, change it between polls.
#[derive(Default)]
pub struct FakeNetStat {
    state: Mutex<State>,
}

impl FakeNetStat {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn set_connections(&self, table: ConnectionTable) {
        self.state().table = table;
    }

    pub fn set_interfaces(&self, interfaces: Vec<InterfaceSample>) {
        self.state().interfaces = interfaces;
    }

    pub fn set_rdp_sessions(&self, sessions: Vec<RdpSession>) {
        self.state().rdp = sessions;
    }

    /// Makes `connections()` fail, to test that a failing source does not stop the poller.
    pub fn set_connections_failing(&self, failing: bool) {
        self.state().fail_connections = failing;
    }
}

impl NetStat for FakeNetStat {
    fn connections(&self) -> io::Result<ConnectionTable> {
        let state = self.state();
        if state.fail_connections {
            return Err(io::Error::other("scripted failure"));
        }
        Ok(state.table.clone())
    }

    fn interfaces(&self) -> io::Result<Vec<InterfaceSample>> {
        Ok(self.state().interfaces.clone())
    }

    fn rdp_sessions(&self) -> io::Result<Vec<RdpSession>> {
        Ok(self.state().rdp.clone())
    }
}
