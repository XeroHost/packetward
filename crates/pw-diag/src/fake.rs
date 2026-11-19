// SPDX-License-Identifier: GPL-3.0-or-later
//! Test doubles: a scripted [`Pinger`] and a scripted DNS backend live here so the
//! engine can reuse them in its own tests.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::dns::{DnsBackend, DnsFailure, DnsRecord, DnsRecordType};
use crate::echo::{EchoReply, EchoRequest, Pinger};
use crate::error::DiagError;

type Script = dyn FnMut(&EchoRequest, u32) -> Result<EchoReply, DiagError> + Send;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic in a test closure must not hide the real failure behind a poisoned-lock panic.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A [`Pinger`] whose answers come from a closure. The closure receives the request and how many
/// earlier requests used the same TTL (for MTR that is the cycle index).
pub struct FakePinger {
    script: Mutex<Box<Script>>,
    log: Mutex<Vec<EchoRequest>>,
    per_ttl: Mutex<HashMap<u8, u32>>,
    delay: Duration,
}

impl std::fmt::Debug for FakePinger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakePinger")
            .field("requests", &lock(&self.log).len())
            .finish()
    }
}

impl FakePinger {
    /// Build from a script closure.
    pub fn new<F>(script: F) -> Self
    where
        F: FnMut(&EchoRequest, u32) -> Result<EchoReply, DiagError> + Send + 'static,
    {
        Self {
            script: Mutex::new(Box::new(script)),
            log: Mutex::new(Vec::new()),
            per_ttl: Mutex::new(HashMap::new()),
            delay: Duration::ZERO,
        }
    }

    /// Make every probe take `delay` (tokio time) before answering.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<EchoRequest> {
        lock(&self.log).clone()
    }
}

impl Pinger for FakePinger {
    async fn echo(&self, request: &EchoRequest) -> Result<EchoReply, DiagError> {
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

type DnsScript = dyn FnMut(&str, DnsRecordType) -> Result<Vec<DnsRecord>, DnsFailure> + Send;

/// A [`DnsBackend`] whose answers come from a closure; records every query it receives.
pub struct FakeDnsBackend {
    script: Mutex<Box<DnsScript>>,
    log: Mutex<Vec<(String, DnsRecordType)>>,
    delay: Duration,
}

impl std::fmt::Debug for FakeDnsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeDnsBackend")
            .field("queries", &lock(&self.log).len())
            .finish()
    }
}

impl FakeDnsBackend {
    /// Build from a script closure `(name, type) -> answer`.
    pub fn new<F>(script: F) -> Self
    where
        F: FnMut(&str, DnsRecordType) -> Result<Vec<DnsRecord>, DnsFailure> + Send + 'static,
    {
        Self {
            script: Mutex::new(Box::new(script)),
            log: Mutex::new(Vec::new()),
            delay: Duration::ZERO,
        }
    }

    /// Make every query take `delay` (tokio time) before answering.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Every `(name, type)` queried so far, in order.
    pub fn queries(&self) -> Vec<(String, DnsRecordType)> {
        lock(&self.log).clone()
    }
}

impl DnsBackend for FakeDnsBackend {
    async fn query(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<Vec<DnsRecord>, DnsFailure> {
        lock(&self.log).push((name.to_owned(), record_type));
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let mut script = lock(&self.script);
        (*script)(name, record_type)
    }
}
