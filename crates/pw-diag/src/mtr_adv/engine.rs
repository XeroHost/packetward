// SPDX-License-Identifier: GPL-3.0-or-later
//! [`mtr_with`]: the advanced entry point. The cycle engine itself is shared with the simple
//! [`crate::mtr()`] (it lives in `mtr.rs`); this adds mode selection, validation and the ASN /
//! country columns.

use std::net::IpAddr;
use std::sync::Arc;

use super::{
    AdvHop, AdvMtrOptions, AdvMtrSnapshot, EnrichCache, HopEnricher, MtrError, ProbeMode,
    ProbeTransport,
};
use crate::cancel::CancelToken;
use crate::mtr::{run_trace, CoreSnapshot};
use crate::names::{NameCache, ReverseLookup};
use crate::sink::Sink;

/// Turns engine snapshots into [`AdvMtrSnapshot`]s (ASN / country looked up through the cache,
/// which only ever consults the local enricher for public addresses).
struct Decorate<'a, E> {
    mode: ProbeMode,
    port: u16,
    enricher: &'a EnrichCache<E>,
}

impl<E: HopEnricher> Decorate<'_, E> {
    fn convert(&self, core: CoreSnapshot) -> AdvMtrSnapshot {
        let CoreSnapshot {
            snapshot,
            reached_via,
        } = core;
        let hops = snapshot
            .hops
            .into_iter()
            .map(|hop| {
                let info = hop.addr.and_then(|a| self.enricher.info(a));
                AdvHop { hop, info }
            })
            .collect();
        AdvMtrSnapshot {
            mode: self.mode,
            port: self.port,
            target: snapshot.target,
            cycle: snapshot.cycle,
            total_cycles: snapshot.total_cycles,
            hops,
            destination_reached: snapshot.destination_reached,
            reached_via,
            cancelled: snapshot.cancelled,
        }
    }
}

struct DecoratingSink<'a, 'b, E, S> {
    decorate: &'b Decorate<'a, E>,
    inner: &'b mut S,
}

impl<E: HopEnricher, S: Sink<AdvMtrSnapshot>> Sink<CoreSnapshot> for DecoratingSink<'_, '_, E, S> {
    async fn deliver(&mut self, item: CoreSnapshot) -> bool {
        let converted = self.decorate.convert(item);
        self.inner.deliver(converted).await
    }
}

/// Trace the route to `target` with the probe mode of `options`, delivering an
/// [`AdvMtrSnapshot`] to `sink` after every cycle, and return the last one.
///
/// * `transport` sends the probes ([`super::PingerTransport`] for ICMP,
///   [`super::SystemProbeTransport`] for everything on a real machine,
///   [`super::FakeProbeTransport`] in tests). A mode it cannot run is reported as
///   [`MtrError::ModeUnavailable`] **before** anything is sent.
/// * `options` are clamped with [`AdvMtrOptions::normalized_for`]; a zero port is refused.
/// * `names` resolves hop names after each cycle unless `options.resolve_names` is `false`
///   (then DNS is never touched).
/// * `enricher` adds ASN / country from a local database; private and reserved addresses are
///   never looked up.
///
/// Cancellation behaves like [`crate::mtr()`]: the returned table covers the completed cycles
/// and has `cancelled == true`. An `Err` means nothing could be sent at all.
pub async fn mtr_with<T, R, E, S>(
    transport: Arc<T>,
    target: IpAddr,
    options: &AdvMtrOptions,
    names: &NameCache<R>,
    enricher: &EnrichCache<E>,
    cancel: &CancelToken,
    sink: &mut S,
) -> Result<AdvMtrSnapshot, MtrError>
where
    T: ProbeTransport + 'static,
    R: ReverseLookup,
    E: HopEnricher,
    S: Sink<AdvMtrSnapshot>,
{
    options.validate()?;
    let opts = options.normalized_for(target);
    let decorate = Decorate {
        mode: opts.mode,
        port: opts.probe_port(),
        enricher,
    };
    let mut sink = DecoratingSink {
        decorate: &decorate,
        inner: sink,
    };
    let last = run_trace(transport, target, &opts, names, cancel, &mut sink).await?;
    Ok(decorate.convert(last))
}
