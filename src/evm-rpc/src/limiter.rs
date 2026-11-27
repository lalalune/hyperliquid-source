//! Node #115 `evm_rpc/src/expensive_call_limiter.rs` reconstruction.
//!
//! Grounded in `research/work-items/RE-011-evm-permit-routing-115`:
//! - Two selectors: `0` (`eth_call`, `eth_estimateGas`) and `1` (filter/logs path).
//! - Semaphore permit count clipped to `0x1fff_ffff_ffff_ffff` (`0x175d250`).
//! - Poll outcomes: `0x28` (Acquired), `0x26` (Closed / TimedOut), `0x29` (Pending).
//! - `eth_getLogs` filter check (`0x2a2cb70`): 5-way `<= 1000` limit on addresses/topics.

/// Maximum semaphore permit count mask observed in `0x175d250`.
pub const MAX_PERMIT_COUNT: usize = 0x1fff_ffff_ffff_ffff;

/// Maximum addresses / topics per filter slot observed in `0x2a2cb70` (5 checks against 1000).
pub const MAX_FILTER_ITEMS: usize = 1000;

/// Metric name emitted by `expensive_call_limiter.rs` (`0x2a04070`, `.rodata` `0x6023ac`).
pub const EXPENSIVE_CALL_PERMIT_METRIC: &str = "evm_rpc_expensive_call_permit";

/// Error prefix returned when any of the 5 `eth_getLogs` filter slots exceeds `MAX_FILTER_ITEMS`
/// (`0x2a2cb70`, `.rodata` `0x433a75`, formatted with `u64(1000)` at `0x459c00`).
pub const LOG_FILTER_LIMIT_ERROR: &str = "query exceeds max addresses or topics per position";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LimiterSelector {
    /// Selector `0`: `eth_call` and `eth_estimateGas`.
    CallOrEstimateGas = 0,
    /// Selector `1`: filter / `eth_getLogs` path (`0x2a2cb70`).
    FilterLogs = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PermitOutcome {
    /// Output byte `0x28`: permit acquired.
    Acquired = 0x28,
    /// Output byte `0x26`: semaphore closed or timed out.
    RejectedOrTimedOut = 0x26,
    /// Output byte `0x29`: pending.
    Pending = 0x29,
}

/// Offline synchronous model of the two-selector permit limiter (`0x2a04070`, `0x175d250`).
#[derive(Clone, Debug)]
pub struct ExpensiveCallLimiter {
    limits: [usize; 2],
    in_flight: [usize; 2],
    timeouts_secs: [f64; 2],
    closed: [bool; 2],
}

impl ExpensiveCallLimiter {
    pub fn new(call_limit: usize, filter_limit: usize, call_timeout_s: f64, filter_timeout_s: f64) -> Self {
        Self {
            limits: [
                call_limit.min(MAX_PERMIT_COUNT),
                filter_limit.min(MAX_PERMIT_COUNT),
            ],
            in_flight: [0, 0],
            timeouts_secs: [call_timeout_s, filter_timeout_s],
            closed: [false, false],
        }
    }

    /// Reconfigure selector limits if changed (clipping to `MAX_PERMIT_COUNT`, `0x175d250`).
    pub fn refresh_limits(&mut self, call_limit: usize, filter_limit: usize) -> [bool; 2] {
        let next = [
            call_limit.min(MAX_PERMIT_COUNT),
            filter_limit.min(MAX_PERMIT_COUNT),
        ];
        let mut changed = [false; 2];
        for i in 0..2 {
            if self.limits[i] != next[i] {
                self.limits[i] = next[i];
                changed[i] = true;
            }
        }
        changed
    }

    pub fn limit(&self, selector: LimiterSelector) -> usize {
        self.limits[selector as usize]
    }

    pub fn timeout_secs(&self, selector: LimiterSelector) -> f64 {
        self.timeouts_secs[selector as usize]
    }

    pub fn close(&mut self, selector: LimiterSelector) {
        self.closed[selector as usize] = true;
    }

    pub fn try_acquire(&mut self, selector: LimiterSelector) -> PermitOutcome {
        let idx = selector as usize;
        if self.closed[idx] {
            return PermitOutcome::RejectedOrTimedOut;
        }
        if self.in_flight[idx] < self.limits[idx] {
            self.in_flight[idx] += 1;
            PermitOutcome::Acquired
        } else {
            PermitOutcome::Pending
        }
    }

    pub fn release(&mut self, selector: LimiterSelector) {
        let idx = selector as usize;
        self.in_flight[idx] = self.in_flight[idx].saturating_sub(1);
    }
}

/// Validate the 5 filter counts (addresses + 4 topic slots) against `MAX_FILTER_ITEMS` (1000),
/// matching the five unsigned comparisons in `0x2a2cb70`.
pub fn validate_log_filter_limits(addresses_len: usize, topic_lens: [usize; 4]) -> bool {
    addresses_len <= MAX_FILTER_ITEMS && topic_lens.iter().all(|&n| n <= MAX_FILTER_ITEMS)
}
