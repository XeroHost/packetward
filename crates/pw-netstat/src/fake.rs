// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! In-memory [`NetStat`] for tests of the engine and anything built on it.

use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

use pw_proto::{LogonAudit, RdpSession, TrustFeed};

use crate::logon::LogonEvent;
use crate::{ConnectionTable, InterfaceSample, LogonSink, NetStat};

#[derive(Default)]
struct State {
    table: ConnectionTable,
    interfaces: Vec<InterfaceSample>,
    rdp: Vec<RdpSession>,
    fail_connections: bool,
    audit: LogonAudit,
    feed_unavailable: bool,
    /// Logons delivered when the feed starts (the "initial load").
    history: Vec<LogonEvent>,
    sink: Option<LogonSink>,
    failure_sink: Option<LogonSink>,
    context: crate::NetworkContext,
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

    pub fn set_logon_audit(&self, audit: LogonAudit) {
        self.state().audit = audit;
    }

    pub fn set_logon_history(&self, history: Vec<LogonEvent>) {
        self.state().history = history;
    }

    pub fn set_logon_feed_unavailable(&self, unavailable: bool) {
        self.state().feed_unavailable = unavailable;
    }

    /// Delivers a live logon event, as a subscription callback would. No-op before the feed starts.
    pub fn push_logon(&self, event: LogonEvent) {
        let sink = self.state().sink.clone();
        if let Some(sink) = sink {
            sink(event);
        }
    }

    /// Delivers a failed logon, as the 4625 subscription would. No-op before the feed starts.
    pub fn push_failure(&self, event: LogonEvent) {
        let sink = self.state().failure_sink.clone();
        if let Some(sink) = sink {
            sink(event);
        }
    }

    pub fn set_network_context(&self, context: crate::NetworkContext) {
        self.state().context = context;
    }

    /// Makes `connections()` fail, to test that a failing source does not stop the poller.
    pub fn set_connections_failing(&self, failing: bool) {
        self.state().fail_connections = failing;
    }
}

impl NetStat for FakeNetStat {
    fn logon_audit(&self) -> LogonAudit {
        self.state().audit
    }

    fn network_context(&self) -> crate::NetworkContext {
        self.state().context.clone()
    }

    fn start_failure_feed(&self, sink: LogonSink) -> bool {
        let mut state = self.state();
        if state.feed_unavailable {
            return false;
        }
        state.failure_sink = Some(sink);
        true
    }

    fn start_logon_feed(&self, _window_ms: u64, sink: LogonSink) -> TrustFeed {
        let history = {
            let mut state = self.state();
            if state.feed_unavailable {
                return TrustFeed::Unavailable;
            }
            state.sink = Some(sink.clone());
            state.history.clone()
        };
        for event in history {
            sink(event);
        }
        TrustFeed::Ready
    }

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
