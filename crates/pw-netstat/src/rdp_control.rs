// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading and changing the Remote Desktop configuration of the machine (RDP Shield, M7b).
//!
//! The trait is what the engine sees; [`FakeRdpControl`] is the in-memory stand-in used by every test;
//! `sys::rdp_control::WindowsRdpControl` talks to the registry, the account policy, the service control
//! manager and the terminal services. **Its write paths are only ever executed on a test VPS**: a wrong
//! value here can cut the administrator off from the machine.

use std::io;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The default RDP port.
pub const DEFAULT_PORT: u16 = 3389;

/// Account lockout policy (`net accounts`). A threshold of 0 means "never lock".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lockout {
    pub threshold: u32,
    pub window_mins: u32,
    pub duration_mins: u32,
}

/// What the machine is configured to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpConfig {
    /// Remote Desktop connections are allowed (`fDenyTSConnections` = 0).
    pub enabled: bool,
    pub port: u16,
    /// Network Level Authentication is required (`UserAuthentication` = 1).
    pub nla_required: bool,
    /// `SecurityLayer`: 0 RDP, 1 negotiate, 2 TLS.
    pub security_layer: u32,
    pub lockout: Lockout,
}

impl Default for RdpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: DEFAULT_PORT,
            nla_required: true,
            security_layer: 1,
            lockout: Lockout::default(),
        }
    }
}

pub trait RdpControl: Send + Sync {
    fn read(&self) -> io::Result<RdpConfig>;
    fn set_port(&self, port: u16) -> io::Result<()>;
    fn set_nla(&self, required: bool) -> io::Result<()>;
    fn set_lockout(&self, lockout: Lockout) -> io::Result<()>;
    /// Restarts the Remote Desktop service so a new port takes effect. **Disconnects every RDP session.**
    fn restart_service(&self) -> io::Result<()>;
    /// Members of the local group `Remote Desktop Users`.
    fn remote_desktop_users(&self) -> io::Result<Vec<String>>;
    /// Disconnects (the session keeps running) or logs off (ends it) a session.
    fn end_session(&self, session_id: u32, logoff: bool) -> io::Result<()>;
}

/// One call the fake received, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpCall {
    SetPort(u16),
    SetNla(bool),
    SetLockout(Lockout),
    RestartService,
    EndSession { id: u32, logoff: bool },
}

#[derive(Default)]
struct FakeState {
    config: RdpConfig,
    users: Vec<String>,
    calls: Vec<RdpCall>,
    fail_next: Option<&'static str>,
}

/// In-memory RDP configuration for tests.
#[derive(Default)]
pub struct FakeRdpControl {
    state: Mutex<FakeState>,
}

impl FakeRdpControl {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn with_config(config: RdpConfig) -> Self {
        let fake = Self::new();
        fake.state().config = config;
        fake
    }

    pub fn set_users(&self, users: Vec<String>) {
        self.state().users = users;
    }

    pub fn calls(&self) -> Vec<RdpCall> {
        self.state().calls.clone()
    }

    /// Makes the next call named `op` (`set_port`, `set_nla`, `set_lockout`, `restart`, `end_session`) fail.
    pub fn fail_next(&self, op: &'static str) {
        self.state().fail_next = Some(op);
    }

    fn check(&self, op: &'static str) -> io::Result<()> {
        let mut state = self.state();
        if state.fail_next == Some(op) {
            state.fail_next = None;
            return Err(io::Error::other(format!("{op} failed")));
        }
        Ok(())
    }
}

impl RdpControl for FakeRdpControl {
    fn read(&self) -> io::Result<RdpConfig> {
        Ok(self.state().config.clone())
    }

    fn set_port(&self, port: u16) -> io::Result<()> {
        self.check("set_port")?;
        let mut state = self.state();
        state.config.port = port;
        state.calls.push(RdpCall::SetPort(port));
        Ok(())
    }

    fn set_nla(&self, required: bool) -> io::Result<()> {
        self.check("set_nla")?;
        let mut state = self.state();
        state.config.nla_required = required;
        state.calls.push(RdpCall::SetNla(required));
        Ok(())
    }

    fn set_lockout(&self, lockout: Lockout) -> io::Result<()> {
        self.check("set_lockout")?;
        let mut state = self.state();
        state.config.lockout = lockout;
        state.calls.push(RdpCall::SetLockout(lockout));
        Ok(())
    }

    fn restart_service(&self) -> io::Result<()> {
        self.check("restart")?;
        self.state().calls.push(RdpCall::RestartService);
        Ok(())
    }

    fn remote_desktop_users(&self) -> io::Result<Vec<String>> {
        Ok(self.state().users.clone())
    }

    fn end_session(&self, session_id: u32, logoff: bool) -> io::Result<()> {
        self.check("end_session")?;
        self.state().calls.push(RdpCall::EndSession {
            id: session_id,
            logoff,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fake_records_changes_in_order_and_can_fail_once() {
        let fake = FakeRdpControl::new();
        fake.set_port(4444).unwrap();
        fake.restart_service().unwrap();
        fake.fail_next("set_nla");
        assert!(fake.set_nla(false).is_err());
        fake.set_nla(false).unwrap();
        assert_eq!(
            fake.calls(),
            [
                RdpCall::SetPort(4444),
                RdpCall::RestartService,
                RdpCall::SetNla(false)
            ]
        );
        assert_eq!(fake.read().unwrap().port, 4444);
        assert!(!fake.read().unwrap().nla_required);
    }
}
