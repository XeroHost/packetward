// SPDX-License-Identifier: GPL-3.0-or-later
//! Fakes for tests, here and in the crates that consume `pw-intel` (enable the `testing` feature).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::{Clock, FetchError, FetchRequest, FetchResponse, Fetcher, UnixSecs};

/// A clock that only moves when told to.
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    pub fn new(start: UnixSecs) -> Self {
        Self(Arc::new(AtomicU64::new(start)))
    }

    pub fn set(&self, now: UnixSecs) {
        self.0.store(now, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> UnixSecs {
        self.0.load(Ordering::SeqCst)
    }
}

type Handler =
    Box<dyn Fn(&FetchRequest) -> Option<Result<FetchResponse, FetchError>> + Send + Sync>;

/// A scripted fetcher. Responses are consumed in order; `route` handlers (matched by URL substring) take
/// precedence and are never consumed. Every request is recorded. An unscripted request fails the test with a
/// network error rather than touching anything.
#[derive(Default)]
pub struct FakeFetcher {
    queue: Mutex<VecDeque<Result<FetchResponse, FetchError>>>,
    routes: Mutex<Vec<Handler>>,
    seen: Mutex<Vec<FetchRequest>>,
}

impl FakeFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue the next response.
    pub fn push(&self, response: Result<FetchResponse, FetchError>) -> &Self {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(response);
        self
    }

    /// Answer every request whose URL contains `needle` with `make(request)`.
    pub fn route(
        &self,
        needle: &str,
        make: impl Fn(&FetchRequest) -> Result<FetchResponse, FetchError> + Send + Sync + 'static,
    ) -> &Self {
        let needle = needle.to_owned();
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Box::new(move |request| {
                request.url.contains(&needle).then(|| make(request))
            }));
        self
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<FetchRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn request_count(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Fetcher for FakeFetcher {
    async fn fetch(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request.clone());
        let routed = {
            let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
            routes.iter().find_map(|handler| handler(&request))
        };
        let result = match routed {
            Some(result) => result,
            None => self
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
                .unwrap_or_else(|| Err(FetchError::Network("no scripted response".to_owned()))),
        };
        // Like the real fetcher, abort a body that exceeds the request's cap.
        match result {
            Ok(response) if response.body.len() > request.max_bytes => Err(FetchError::TooLarge {
                limit: request.max_bytes,
            }),
            other => other,
        }
    }
}

/// Captures every `tracing` event and span field emitted on the current thread into a string, so tests can assert
/// that something (an API key) never reaches a log line.
#[derive(Debug, Clone, Default)]
pub struct LogCapture(Arc<Mutex<String>>);

struct CaptureSubscriber {
    buffer: Arc<Mutex<String>>,
    next_id: AtomicU64,
}

struct FieldWriter<'a>(&'a mut String);

impl tracing::field::Visit for FieldWriter<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl CaptureSubscriber {
    fn push(&self, write: impl FnOnce(&mut String)) {
        let mut line = String::new();
        write(&mut line);
        line.push('\n');
        self.buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_str(&line);
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.push(|line| {
            line.push_str(attributes.metadata().name());
            attributes.record(&mut FieldWriter(line));
        });
        tracing::span::Id::from_u64(self.next_id.fetch_add(1, Ordering::SeqCst))
    }

    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.push(|line| values.record(&mut FieldWriter(line)));
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        self.push(|line| {
            line.push_str(event.metadata().target());
            event.record(&mut FieldWriter(line));
        });
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Process-wide subscriber that records nothing but answers "maybe" for every callsite. Without it, a callsite first
/// hit by a parallel test thread that has no subscriber is cached as "never enabled", and a later scoped
/// [`LogCapture`] would silently see nothing (a flaky test, not a failure).
struct Passive;

impl tracing::Subscriber for Passive {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, _: &tracing::Event<'_>) {}

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

impl LogCapture {
    /// Install a capturing subscriber for the current thread until the guard is dropped.
    ///
    /// Side effect: the first call also installs a process-wide no-op subscriber. A test binary that later calls
    /// `tracing_subscriber::fmt().init()` would panic; use `try_init()` there.
    pub fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        static GLOBAL: std::sync::Once = std::sync::Once::new();
        GLOBAL.call_once(|| {
            // Fails harmlessly when the test binary already installed its own global subscriber.
            let _ = tracing::subscriber::set_global_default(Passive);
        });
        let capture = Self::default();
        let subscriber = CaptureSubscriber {
            buffer: Arc::clone(&capture.0),
            next_id: AtomicU64::new(1),
        };
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    pub fn contents(&self) -> String {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
