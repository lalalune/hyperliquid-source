//! Independently authored `#![forbid(unsafe_code)]` Rust reconstruction of node
//! #115's `node/src/consensus/heartbeat_tracker.rs` (`0x5a71e20..0x5a71ed9`, 185 B;
//! `0x5a71ee0..0x5a722ec`, 1,036 B).
//!
//! Direct binary anchors verified in `RE-008-node115-consensus-closure`:
//! - `0x5a71e20` (185 B): checks the periodic bucket guard at `[tracker+0xb0]`
//!   (`call 0x57d37c0`), reads wall-clock `Time` (`call *0x64e0990`), and
//!   updates per-validator heartbeat observations (`call 0x4d55380`).
//! - `0x5a71ee0` (1,036 B): reads wall-clock `Time` (`call *0x64e0990`),
//!   subtracts `0xb4` (**180 seconds** = 3 minutes) at `0x5a71f10` (`mov $0xb4, %edx;
//!   call *0x64e0f78`), and emits/persists the `"validator_latency_ema"`
//!   (`.rodata 0x93b1d7`, len `0x15` = 21 B) latency snapshot under
//!   `/file_mod_time_tracker/` (`.json`).

use std::collections::BTreeMap;

use crate::round_progression::Address;

/// Lookback window in seconds subtracted from current wall-clock time in
/// `0x5a71f10` (`mov $0xb4, %edx; call *0x64e0f78`).
pub const HEARTBEAT_WINDOW_SECS: u64 = 180;

/// Exact `.rodata` key literal at `0x93b1d7` (`len = 0x15 = 21`) loaded at
/// `0x5a7203c..0x5a72050` in `heartbeat_tracker.rs`.
pub const VALIDATOR_LATENCY_EMA_KEY: &str = "validator_latency_ema";

/// Per-validator heartbeat liveness & latency EMA state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ValidatorHeartbeatRecord {
    pub last_seen_secs: u64,
    pub latency_ema_ms: f64,
    pub sample_count: u64,
}

/// Cohesive heartbeat liveness & validator latency EMA tracker modeling
/// `node/src/consensus/heartbeat_tracker.rs` (`0x5a71e20` / `0x5a71ee0`).
#[derive(Clone, Debug, PartialEq)]
pub struct HeartbeatTracker {
    pub ema_alpha: f64,
    pub window_secs: u64,
    pub last_bucket: Option<u64>,
    pub validators: BTreeMap<Address, ValidatorHeartbeatRecord>,
}

impl Default for HeartbeatTracker {
    fn default() -> Self {
        Self::new(0.2)
    }
}

impl HeartbeatTracker {
    pub fn new(ema_alpha: f64) -> Self {
        Self {
            ema_alpha: ema_alpha.clamp(0.0, 1.0),
            window_secs: HEARTBEAT_WINDOW_SECS,
            last_bucket: None,
            validators: BTreeMap::new(),
        }
    }

    /// Evaluates the monotonic periodic bucket guard at `[tracker+0xb0]`
    /// (`0x5a71e36..0x5a71e47`): returns `true` iff `bucket` strictly advances
    /// past `last_bucket`.
    pub fn check_periodic_bucket(&mut self, now_secs: u64, period_secs: u64) -> bool {
        if period_secs == 0 {
            return false;
        }
        let bucket = now_secs / period_secs;
        match self.last_bucket {
            Some(prev) if bucket <= prev => false,
            _ => {
                self.last_bucket = Some(bucket);
                true
            }
        }
    }

    /// Records a heartbeat acknowledgement from `validator` at `now_secs` with
    /// measured RTT/latency `latency_ms` (non-finite or negative latencies are
    /// ignored for EMA updates while still updating `last_seen_secs`).
    pub fn record_heartbeat(&mut self, validator: Address, now_secs: u64, latency_ms: f64) {
        let valid_latency = latency_ms.is_finite() && latency_ms >= 0.0;
        self.validators
            .entry(validator)
            .and_modify(|rec| {
                if now_secs > rec.last_seen_secs {
                    rec.last_seen_secs = now_secs;
                }
                if valid_latency {
                    rec.latency_ema_ms =
                        self.ema_alpha * latency_ms + (1.0 - self.ema_alpha) * rec.latency_ema_ms;
                    rec.sample_count = rec.sample_count.saturating_add(1);
                }
            })
            .or_insert_with(|| ValidatorHeartbeatRecord {
                last_seen_secs: now_secs,
                latency_ema_ms: if valid_latency { latency_ms } else { 0.0 },
                sample_count: u64::from(valid_latency),
            });
    }

    /// Returns the cutoff timestamp `now_secs.saturating_sub(self.window_secs)`
    /// matching `0x5a71f10` (`now - 180s`).
    pub const fn liveness_cutoff_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.window_secs)
    }

    /// Returns all tracked validators whose `last_seen_secs < cutoff` (stale
    /// beyond the 180-second heartbeat window).
    pub fn stale_validators(&self, now_secs: u64) -> Vec<Address> {
        let cutoff = self.liveness_cutoff_secs(now_secs);
        self.validators
            .iter()
            .filter_map(|(&addr, rec)| (rec.last_seen_secs < cutoff).then_some(addr))
            .collect()
    }

    /// Produces the `"validator_latency_ema"` map for live validators inside
    /// the `[now - 180s, now]` window.
    pub fn active_latency_ema_snapshot(&self, now_secs: u64) -> BTreeMap<Address, f64> {
        let cutoff = self.liveness_cutoff_secs(now_secs);
        self.validators
            .iter()
            .filter_map(|(&addr, rec)| {
                (rec.last_seen_secs >= cutoff && rec.sample_count > 0)
                    .then_some((addr, rec.latency_ema_ms))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_tracker_window_180s_and_ema_snapshot() {
        let mut tracker = HeartbeatTracker::new(0.5);
        assert_eq!(tracker.window_secs, 180);
        assert_eq!(VALIDATOR_LATENCY_EMA_KEY, "validator_latency_ema");

        assert!(tracker.check_periodic_bucket(100, 60));
        assert!(!tracker.check_periodic_bucket(119, 60));
        assert!(tracker.check_periodic_bucket(120, 60));

        let v1 = [0x01; 20];
        let v2 = [0x02; 20];
        tracker.record_heartbeat(v1, 100, 20.0);
        tracker.record_heartbeat(v1, 200, 40.0);
        tracker.record_heartbeat(v2, 50, 15.0);

        // At t = 250, cutoff = 70: v2 (t=50) is stale, v1 (t=200) is live with EMA = 30.0.
        assert_eq!(tracker.liveness_cutoff_secs(250), 70);
        assert_eq!(tracker.stale_validators(250), vec![v2]);
        let snap = tracker.active_latency_ema_snapshot(250);
        assert_eq!(snap.len(), 1);
        assert!((snap[&v1] - 30.0).abs() < 1e-12);
    }
}
