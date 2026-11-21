// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Pure refresh scheduling: no clock reads, no I/O. Time is always passed in.

use serde::{Deserialize, Serialize};

use crate::UnixSecs;

/// Public lists ask not to be polled more often than this.
pub const MIN_REFRESH_SECS: u64 = 3600;
pub const MAX_REFRESH_SECS: u64 = 30 * 24 * 3600;
const RETRY_BASE_SECS: u64 = 5 * 60;
const RETRY_CAP_SECS: u64 = 6 * 3600;

/// What the scheduler needs to know about one list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleState {
    pub last_attempt: Option<UnixSecs>,
    pub last_success: Option<UnixSecs>,
    pub consecutive_failures: u32,
}

pub fn clamp_interval(secs: u64) -> u64 {
    secs.clamp(MIN_REFRESH_SECS, MAX_REFRESH_SECS)
}

/// Delay before retrying after `consecutive_failures` failures in a row: 5 min, 10, 20, … capped at 6 h
/// (and never longer than the normal interval, see [`next_attempt`]).
pub fn retry_delay_secs(consecutive_failures: u32) -> u64 {
    let exponent = consecutive_failures.saturating_sub(1).min(16);
    RETRY_BASE_SECS
        .saturating_mul(1u64 << exponent)
        .min(RETRY_CAP_SECS)
}

/// When the next refresh should happen. `0` means "as soon as possible" (never attempted).
pub fn next_attempt(state: &ScheduleState, interval_secs: u64) -> UnixSecs {
    let interval = clamp_interval(interval_secs);
    match (state.last_attempt, state.consecutive_failures) {
        (None, _) => 0,
        (Some(attempt), 0) => state
            .last_success
            .unwrap_or(attempt)
            .saturating_add(interval),
        (Some(attempt), failures) => {
            attempt.saturating_add(retry_delay_secs(failures).min(interval))
        }
    }
}

/// `true` when a refresh is due at `now`. A last attempt in the future (the clock was set back) counts as due,
/// so a bad clock can never freeze updates.
pub fn is_due(state: &ScheduleState, interval_secs: u64, now: UnixSecs) -> bool {
    if state.last_attempt.is_some_and(|attempt| attempt > now) {
        return true;
    }
    now >= next_attempt(state, interval_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_attempted_is_due_immediately() {
        assert!(is_due(&ScheduleState::default(), 86_400, 0));
        assert_eq!(next_attempt(&ScheduleState::default(), 86_400), 0);
    }

    #[test]
    fn success_waits_one_interval() {
        let state = ScheduleState {
            last_attempt: Some(1_000),
            last_success: Some(1_000),
            consecutive_failures: 0,
        };
        assert!(!is_due(&state, 7_200, 1_000 + 7_199));
        assert!(is_due(&state, 7_200, 1_000 + 7_200));
    }

    #[test]
    fn failures_back_off_exponentially_but_never_beyond_the_interval() {
        assert_eq!(retry_delay_secs(1), 300);
        assert_eq!(retry_delay_secs(2), 600);
        assert_eq!(retry_delay_secs(3), 1_200);
        assert_eq!(retry_delay_secs(40), RETRY_CAP_SECS);
        let state = |failures| ScheduleState {
            last_attempt: Some(10_000),
            last_success: Some(1),
            consecutive_failures: failures,
        };
        assert_eq!(next_attempt(&state(1), 86_400), 10_300);
        assert_eq!(next_attempt(&state(2), 86_400), 10_600);
        // With a 1 h interval a long streak of failures still retries after 1 h at most.
        assert_eq!(next_attempt(&state(10), 3_600), 10_000 + 3_600);
    }

    #[test]
    fn intervals_are_clamped() {
        assert_eq!(clamp_interval(1), MIN_REFRESH_SECS);
        assert_eq!(clamp_interval(u64::MAX), MAX_REFRESH_SECS);
        let state = ScheduleState {
            last_attempt: Some(0),
            last_success: Some(0),
            consecutive_failures: 0,
        };
        // A 1-second "interval" from a corrupt setting still waits an hour.
        assert!(!is_due(&state, 1, 100));
        assert!(is_due(&state, 1, MIN_REFRESH_SECS));
    }

    #[test]
    fn a_clock_set_back_does_not_freeze_updates() {
        let state = ScheduleState {
            last_attempt: Some(5_000_000),
            last_success: Some(5_000_000),
            consecutive_failures: 0,
        };
        assert!(is_due(&state, 86_400, 1_000));
    }

    #[test]
    fn huge_timestamps_do_not_overflow() {
        let state = ScheduleState {
            last_attempt: Some(u64::MAX - 1),
            last_success: Some(u64::MAX - 1),
            consecutive_failures: 0,
        };
        assert_eq!(next_attempt(&state, 86_400), u64::MAX);
    }
}
