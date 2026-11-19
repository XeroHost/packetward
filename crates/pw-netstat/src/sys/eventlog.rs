// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows event log access: a bounded initial load plus live `EvtSubscribe` subscriptions for
//! successful RDP logons, and the "Audit Logon" policy. No searching of the whole log, no `wevtutil`.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pw_proto::{AuditState, LogonAudit, TrustFeed};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Security::Authentication::Identity::{
    AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION,
};
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents,
    EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
};

use crate::logon::{parse_failed_logon_event, parse_logon_event, LogonEvent};
use crate::LogonSink;

const SECURITY_CHANNEL: &str = "Security";
const TERMINAL_SERVICES_CHANNEL: &str =
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

/// LogonType 10 (RemoteInteractive: a new RDP session) or 7 (an RDP *reconnect*; the parser ignores
/// type 7 without a remote address, i.e. a local console unlock).
const LOGON_TYPES: &str = "(Data[@Name='LogonType']='10' or Data[@Name='LogonType']='7')";
/// 4624 with one of those logon types.
const SECURITY_FILTER: &str = "*[System[(EventID=4624)] and EventData[(Data[@Name='LogonType']='10' or Data[@Name='LogonType']='7')]]";
/// 1149: "Remote Desktop Services: User authentication succeeded".
const TERMINAL_SERVICES_FILTER: &str = "*[System[(EventID=1149)]]";

/// The initial load reads at most this many events and takes at most this long: nothing here may
/// turn into a long search of a big log.
const INITIAL_MAX_EVENTS: usize = 5_000;
const INITIAL_MAX_TIME: Duration = Duration::from_secs(10);
const BATCH: usize = 64;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn code(err: &windows::core::Error) -> u32 {
    (err.code().0 as u32) & 0xFFFF
}

/// Renders an event handle to its XML text.
fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut properties = 0u32;
    // SAFETY: sizing call with no buffer.
    let sizing = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used,
            &mut properties,
        )
    };
    match sizing {
        Err(err) if code(&err) == ERROR_INSUFFICIENT_BUFFER => {}
        _ => return None,
    }
    let mut buffer = vec![0u16; (used as usize).div_ceil(2) + 1];
    // SAFETY: `buffer` holds at least `used` bytes.
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            u32::try_from(buffer.len() * 2).ok()?,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            &mut used,
            &mut properties,
        )
    }
    .ok()?;
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..end]))
}

/// What the subscription callback needs: where to send parsed logons.
struct Context {
    sink: LogonSink,
    /// Turns a rendered event into a logon (success or failure feeds use different parsers).
    parse: fn(&str) -> Option<LogonEvent>,
}

/// A live `EvtSubscribe` subscription; closing it stops the callbacks.
struct Subscription {
    handle: EVT_HANDLE,
    context: *mut Context,
}

// SAFETY: the raw pointer is only dereferenced by the callback (read-only) and freed in Drop after
// the subscription is closed; the handle is an opaque OS token.
unsafe impl Send for Subscription {}

impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: closing the handle stops callbacks, after which the context is no longer used and
        // is freed exactly once.
        unsafe {
            let _ = EvtClose(self.handle);
            drop(Box::from_raw(self.context));
        }
    }
}

unsafe extern "system" fn on_event(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    context: *const c_void,
    event: EVT_HANDLE,
) -> u32 {
    if action == EvtSubscribeActionDeliver && !context.is_null() {
        // SAFETY: `context` is the Context leaked in `subscribe`, alive until the subscription is closed.
        let context = unsafe { &*context.cast::<Context>() };
        // A panic must never unwind into Windows.
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Some(logon) = render_xml(event).as_deref().and_then(context.parse) {
                (context.sink)(logon);
            }
        }));
    }
    0
}

fn subscribe(
    channel: &str,
    query: &str,
    sink: &LogonSink,
    parse: fn(&str) -> Option<LogonEvent>,
) -> Result<Subscription, windows::core::Error> {
    let context = Box::into_raw(Box::new(Context {
        sink: Arc::clone(sink),
        parse,
    }));
    let channel = wide(channel);
    let query = wide(query);
    // SAFETY: valid NUL-terminated strings; `context` stays alive until the Subscription is dropped.
    let handle = unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            None,
            Some(context.cast_const().cast::<c_void>()),
            Some(on_event),
            EvtSubscribeToFutureEvents.0,
        )
    };
    match handle {
        Ok(handle) => Ok(Subscription { handle, context }),
        Err(err) => {
            // SAFETY: the subscription failed, so nothing else references the context.
            unsafe { drop(Box::from_raw(context)) };
            Err(err)
        }
    }
}

/// Reads the newest events of a channel that match `query`, within the bounds above.
fn initial_load(channel: &str, query: &str, sink: &LogonSink, deadline: Instant) -> usize {
    let channel = wide(channel);
    let query = wide(query);
    // SAFETY: valid NUL-terminated strings.
    let Ok(results) = (unsafe {
        EvtQuery(
            None,
            PCWSTR(channel.as_ptr()),
            PCWSTR(query.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    }) else {
        return 0;
    };
    let mut delivered = 0usize;
    let mut batch = [0isize; BATCH];
    'outer: while delivered < INITIAL_MAX_EVENTS && Instant::now() < deadline {
        let mut returned = 0u32;
        // SAFETY: `batch` has room for BATCH handles.
        let next = unsafe { EvtNext(results, &mut batch, 1000, 0, &mut returned) };
        if let Err(err) = next {
            if code(&err) != ERROR_NO_MORE_ITEMS {
                tracing::debug!(%err, "event log read stopped");
            }
            break;
        }
        for &raw in &batch[..returned as usize] {
            let event = EVT_HANDLE(raw);
            if let Some(logon) = render_xml(event).as_deref().and_then(parse_logon_event) {
                sink(logon);
                delivered += 1;
            }
            // SAFETY: closing a handle returned by EvtNext, once.
            unsafe {
                let _ = EvtClose(event);
            }
            if delivered >= INITIAL_MAX_EVENTS {
                break 'outer;
            }
        }
    }
    // SAFETY: closing the result set opened above, once.
    unsafe {
        let _ = EvtClose(results);
    }
    delivered
}

/// The subscriptions that keep the trust set current; dropping it stops them.
pub struct LogonFeed {
    _subscriptions: Vec<Subscription>,
}

/// Subscribes to new RDP logon events first (so none is missed), then loads recent history within a
/// fixed budget. `Unavailable` when the Security log cannot be subscribed to.
pub fn start_feed(window_ms: u64, sink: LogonSink) -> (TrustFeed, Option<LogonFeed>) {
    let mut subscriptions = Vec::new();
    match subscribe(SECURITY_CHANNEL, SECURITY_FILTER, &sink, parse_logon_event) {
        Ok(subscription) => subscriptions.push(subscription),
        Err(err) => {
            tracing::warn!(%err, "cannot subscribe to the Security log; RDP logons will not be learned");
            return (TrustFeed::Unavailable, None);
        }
    }
    // The Terminal Services channel is a second, optional source (it can be disabled).
    match subscribe(
        TERMINAL_SERVICES_CHANNEL,
        TERMINAL_SERVICES_FILTER,
        &sink,
        parse_logon_event,
    ) {
        Ok(subscription) => subscriptions.push(subscription),
        Err(err) => tracing::debug!(%err, "no Terminal Services event channel"),
    }

    let deadline = Instant::now() + INITIAL_MAX_TIME;
    let window = format!("TimeCreated[timediff(@SystemTime) <= {window_ms}]");
    let security_history =
        format!("*[System[(EventID=4624) and {window}] and EventData[{LOGON_TYPES}]]");
    let ts_history = format!("*[System[(EventID=1149) and {window}]]");
    let loaded = initial_load(SECURITY_CHANNEL, &security_history, &sink, deadline)
        + initial_load(TERMINAL_SERVICES_CHANNEL, &ts_history, &sink, deadline);
    tracing::info!(loaded, "loaded recent RDP logons from the event log");
    (
        TrustFeed::Ready,
        Some(LogonFeed {
            _subscriptions: subscriptions,
        }),
    )
}

/// 4625 (an account failed to log on) from the network, remote interactive or reconnect.
const FAILURE_FILTER: &str = "*[System[(EventID=4625)] and EventData[(Data[@Name='LogonType']='3' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10')]]";

/// The live subscription of failed logons; dropping it stops it.
pub struct FailureFeed {
    _subscription: Subscription,
}

/// Subscribes to *new* failed logons (no history: brute force is judged in real time). `None` when the
/// Security log cannot be subscribed to.
pub fn start_failure_feed(sink: &LogonSink) -> Option<FailureFeed> {
    match subscribe(
        SECURITY_CHANNEL,
        FAILURE_FILTER,
        sink,
        parse_failed_logon_event,
    ) {
        Ok(subscription) => Some(FailureFeed {
            _subscription: subscription,
        }),
        Err(err) => {
            tracing::warn!(%err, "cannot subscribe to failed logons; RDP brute force will not be detected");
            None
        }
    }
}

/// The "Audit Logon" subcategory (events 4624/4625).
pub fn logon_audit() -> LogonAudit {
    let guids = [GUID::from_u128(0x0CCE9215_69AE_11D9_BED3_505054503030)];
    let mut policy: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
    // SAFETY: valid GUID slice and out pointer; the result is freed below.
    let ok = unsafe { AuditQuerySystemPolicy(&guids, &mut policy) };
    if !ok || policy.is_null() {
        return LogonAudit::default();
    }
    // SAFETY: on success `policy` points to one AUDIT_POLICY_INFORMATION.
    let flags = unsafe { (*policy).AuditingInformation };
    // SAFETY: freeing the buffer the call allocated, once.
    unsafe { AuditFree(policy.cast_const().cast::<c_void>()) };
    let state = |bit: u32| {
        if flags & bit != 0 {
            AuditState::Enabled
        } else {
            AuditState::Disabled
        }
    };
    LogonAudit {
        success: state(1), // POLICY_AUDIT_EVENT_SUCCESS
        failure: state(2), // POLICY_AUDIT_EVENT_FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a few real Security events (read-only) and checks the rendered XML has the shape the
    /// parser relies on. Skips quietly when the log cannot be read (not elevated, other OS image).
    #[test]
    fn real_rendered_events_have_the_expected_shape() {
        let channel = wide(SECURITY_CHANNEL);
        let query = wide("*[System[(EventID=4624)]]");
        // SAFETY: valid NUL-terminated strings.
        let Ok(results) = (unsafe {
            EvtQuery(
                None,
                PCWSTR(channel.as_ptr()),
                PCWSTR(query.as_ptr()),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
        }) else {
            eprintln!("cannot read the Security log here; skipping");
            return;
        };
        let mut batch = [0isize; 3];
        let mut returned = 0u32;
        // SAFETY: `batch` has room for 3 handles.
        if unsafe { EvtNext(results, &mut batch, 2000, 0, &mut returned) }.is_err() || returned == 0
        {
            eprintln!("no 4624 events to inspect; skipping");
            return;
        }
        for &raw in &batch[..returned as usize] {
            let xml = render_xml(EVT_HANDLE(raw)).expect("event renders");
            assert!(xml.contains("<EventID"), "{xml}");
            assert!(xml.contains("SystemTime="), "{xml}");
            assert!(
                crate::logon::parse_system_time(
                    xml.split("SystemTime='")
                        .nth(1)
                        .and_then(|t| t.split('\'').next())
                        .unwrap_or("")
                )
                .is_some(),
                "time parses: {xml}"
            );
            assert!(xml.contains("Name='LogonType'"), "{xml}");
            assert!(xml.contains("Name='IpAddress'"), "{xml}");
            // SAFETY: closing handles returned by EvtNext.
            unsafe {
                let _ = EvtClose(EVT_HANDLE(raw));
            }
        }
        // SAFETY: closing the result set opened above.
        unsafe {
            let _ = EvtClose(results);
        }
    }

    #[test]
    fn the_audit_policy_can_be_read() {
        let audit = logon_audit();
        println!("logon audit: {audit:?}");
        // Either a real answer or an honest Unknown, never a made-up one.
        assert_eq!(
            audit.success == AuditState::Unknown,
            audit.failure == AuditState::Unknown
        );
    }
}
