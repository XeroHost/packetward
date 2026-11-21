// SPDX-License-Identifier: GPL-3.0-or-later
//! Whether anyone is looking. The desktop UI subscribes to `live.stats` while it is open; when
//! nobody does (the machine is protected, nobody is connected), the engine polls the network and
//! ticks the detectors at a slower pace, which is most of the agent's idle CPU. A new viewer wakes
//! the loops at once, so the first picture is never stale for long. (The first viewer costs one extra poll.)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Debug, Default)]
pub struct Presence {
    watchers: AtomicUsize,
    wake: Notify,
}

impl Presence {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Somebody is looking at the live data.
    pub fn watching(&self) -> bool {
        self.watchers.load(Ordering::Relaxed) > 0
    }

    /// Registers a viewer until the returned guard is dropped, and wakes the loops.
    pub fn enter(self: &Arc<Self>) -> Watcher {
        self.watchers.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_waiters();
        // A loop that was not waiting yet (between two waits) still sees it.
        self.wake.notify_one();
        Watcher(Arc::clone(self))
    }

    /// How long a loop should sleep before its next pass.
    pub fn pace(&self, busy: Duration, idle: Duration) -> Duration {
        if self.watching() {
            busy
        } else {
            idle.max(busy)
        }
    }

    /// Sleeps for `pace`, or less when a viewer arrives meanwhile.
    pub async fn sleep(&self, busy: Duration, idle: Duration) {
        tokio::select! {
            () = tokio::time::sleep(self.pace(busy, idle)) => {}
            () = self.wake.notified() => {}
        }
    }
}

/// A registered viewer; dropping it unregisters.
#[derive(Debug)]
pub struct Watcher(Arc<Presence>);

impl Drop for Watcher {
    fn drop(&mut self) {
        self.0.watchers.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUSY: Duration = Duration::from_millis(10);
    const IDLE: Duration = Duration::from_secs(3600);

    #[test]
    fn nobody_watching_means_the_idle_pace() {
        let presence = Presence::new();
        assert!(!presence.watching());
        assert_eq!(presence.pace(BUSY, IDLE), IDLE);
        let first = presence.enter();
        let second = presence.enter();
        assert_eq!(presence.pace(BUSY, IDLE), BUSY);
        drop(first);
        assert!(presence.watching(), "one viewer is still there");
        drop(second);
        assert!(!presence.watching());
        assert_eq!(presence.pace(BUSY, IDLE), IDLE);
    }

    #[test]
    fn the_idle_pace_is_never_faster_than_the_busy_one() {
        let presence = Presence::new();
        assert_eq!(
            presence.pace(Duration::from_secs(5), Duration::from_secs(1)),
            Duration::from_secs(5)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_viewer_wakes_a_sleeping_loop_at_once() {
        let presence = Presence::new();
        let waiting = {
            let presence = Arc::clone(&presence);
            tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                presence.sleep(BUSY, IDLE).await;
                start.elapsed()
            })
        };
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _watcher = presence.enter();
        let slept = waiting.await.unwrap();
        assert!(
            slept < Duration::from_secs(60),
            "woken early, not after the idle hour: {slept:?}"
        );
    }
}
