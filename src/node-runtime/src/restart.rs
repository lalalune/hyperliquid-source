//! Restart backoff and startup directory admission matching node #115
//! `node115-restart-delay`, `node115-restart-threshold`, `node115-startup-admission`,
//! `node115-startup-path-join`, and `node115-startup-sorted-admission`.

pub use node115_restart_delay::{WaitPlan, delay_seconds, first_wait};
pub use node115_restart_threshold::{Counters, Machine, Phase, Ports, ReadyInputs, SlicePoll};
pub use node115_startup_admission::{self as startup_admission, Entry, Metadata, View};
pub use node115_startup_path_join as startup_path_join;
pub use node115_startup_sorted_admission as startup_sorted_admission;

/// Default restart backoff cap (`30.0` seconds) observed in node #115 `node115-restart-delay`.
pub const DEFAULT_RESTART_CAP_SECS: f64 = 30.0;

/// Restart supervisor combining node #115's exponential backoff (`min(2^counter, cap) - 1`)
/// with the restart attempt counter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RestartSupervisor {
    pub attempts: u64,
    pub cap_secs: f64,
}

impl Default for RestartSupervisor {
    fn default() -> Self {
        Self {
            attempts: 0,
            cap_secs: DEFAULT_RESTART_CAP_SECS,
        }
    }
}

impl RestartSupervisor {
    pub fn new(cap_secs: f64) -> Self {
        Self {
            attempts: 0,
            cap_secs,
        }
    }

    pub fn next_wait(&mut self) -> WaitPlan {
        let plan = first_wait(self.attempts, self.cap_secs);
        self.attempts = self.attempts.saturating_add(1);
        plan
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
    }
}
