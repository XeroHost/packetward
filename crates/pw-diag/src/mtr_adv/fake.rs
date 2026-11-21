// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! A scripted [`ProbeTransport`] for tests (public so the engine and integration tests can use it).

use std::collections::HashMap;
use std::mem::discriminant;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::{ModeUnavailable, MtrError, ProbeMode, ProbeReply, ProbeRequest, ProbeTransport};

type Script = dyn FnMut(&ProbeRequest, u32) -> Result<ProbeReply, MtrError> + Send;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic in a test closure must not hide the real failure behind a poisoned-lock panic.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A [`ProbeTransport`] whose answers come from a closure. The closure receives the request and
/// how many earlier requests used the same TTL (for MTR that is the cycle index).
pub struct FakeProbeTransport {
    script: Mutex<Box<Script>>,
    log: Mutex<Vec<ProbeRequest>>,
    per_ttl: Mutex<HashMap<u8, u32>>,
    delay: Duration,
    unavailable: Option<ModeUnavailable>,
    prepared: Mutex<Vec<(ProbeMode, IpAddr)>>,
}

impl std::fmt::Debug for FakeProbeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeProbeTransport")
            .field("requests", &lock(&self.log).len())
            .finish()
    }
}

impl FakeProbeTransport {
    /// Build from a script closure.
    pub fn new<F>(script: F) -> Self
    where
        F: FnMut(&ProbeRequest, u32) -> Result<ProbeReply, MtrError> + Send + 'static,
    {
        Self {
            script: Mutex::new(Box::new(script)),
            log: Mutex::new(Vec::new()),
            per_ttl: Mutex::new(HashMap::new()),
            delay: Duration::ZERO,
            unavailable: None,
            prepared: Mutex::new(Vec::new()),
        }
    }

    /// Make every probe take `delay` (tokio time) before answering.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Refuse the mode of `unavailable` (same kind; a TCP port does not matter) in
    /// [`ProbeTransport::prepare`], like a transport without a capture backend.
    #[must_use]
    pub fn with_unavailable(mut self, unavailable: ModeUnavailable) -> Self {
        self.unavailable = Some(unavailable);
        self
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<ProbeRequest> {
        lock(&self.log).clone()
    }

    /// Every `(mode, target)` the engine asked this transport to prepare.
    pub fn prepared(&self) -> Vec<(ProbeMode, IpAddr)> {
        lock(&self.prepared).clone()
    }
}

impl ProbeTransport for FakeProbeTransport {
    fn prepare(&self, mode: ProbeMode, target: IpAddr) -> Result<(), ModeUnavailable> {
        lock(&self.prepared).push((mode, target));
        match &self.unavailable {
            Some(u) if discriminant(&u.mode) == discriminant(&mode) => {
                Err(ModeUnavailable::new(mode, u.reason.clone()))
            }
            _ => Ok(()),
        }
    }

    async fn probe(&self, request: &ProbeRequest) -> Result<ProbeReply, MtrError> {
        lock(&self.log).push(request.clone());
        let nth = {
            let mut map = lock(&self.per_ttl);
            let slot = map.entry(request.ttl).or_insert(0);
            let n = *slot;
            *slot += 1;
            n
        };
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let mut script = lock(&self.script);
        (*script)(request, nth)
    }
}
