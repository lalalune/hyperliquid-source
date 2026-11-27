//! Bucketed per-IP + global rate limiter matching node #115
//! `net_utils/src/rate_limiter.rs` (`0x59db700..0x59dbc1d`, `AlertConfig` at `0x7e1c28`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Alert configuration observed in `.rodata` `0x7e1c28` (`struct AlertConfig`,
/// `bucket_limit_mult_threshold`, `ip_rate_limiter_alert_config`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AlertConfig {
    pub bucket_limit_mult_threshold: f64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            bucket_limit_mult_threshold: 2.0,
        }
    }
}

/// Rate-limit admission result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    AllowedWithAlert,
    RejectedPerIp,
    RejectedGlobal,
}

/// Per-IP + global sliding-window byte/request rate limiter with periodic window
/// reset clearing all per-IP maps (matching `0x59db700`).
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    window_start: Instant,
    per_ip_bytes_limit: u64,
    global_bytes_limit: u64,
    alert_config: Option<AlertConfig>,
    ip_bytes: HashMap<IpAddr, u64>,
    ip_rejected_bytes: HashMap<IpAddr, u64>,
    ip_requests: HashMap<IpAddr, u64>,
    ip_alerts: HashMap<IpAddr, u64>,
    global_bytes: u64,
}

impl RateLimiter {
    pub fn new(
        window: Duration,
        per_ip_bytes_limit: u64,
        global_bytes_limit: u64,
        alert_config: Option<AlertConfig>,
    ) -> Self {
        Self {
            window,
            window_start: Instant::now(),
            per_ip_bytes_limit,
            global_bytes_limit,
            alert_config,
            ip_bytes: HashMap::new(),
            ip_rejected_bytes: HashMap::new(),
            ip_requests: HashMap::new(),
            ip_alerts: HashMap::new(),
            global_bytes: 0,
        }
    }

    /// Clear all per-IP buckets and reset the window anchor (matching `0x59db700`).
    pub fn reset_window(&mut self, now: Instant) {
        self.ip_bytes.clear();
        self.ip_rejected_bytes.clear();
        self.ip_requests.clear();
        self.ip_alerts.clear();
        self.global_bytes = 0;
        self.window_start = now;
    }

    pub fn maybe_reset(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= self.window {
            self.reset_window(now);
        }
    }

    /// Check and charge `bytes` for `ip` at timestamp `now`.
    pub fn check_and_charge(&mut self, ip: IpAddr, bytes: u64, now: Instant) -> RateLimitDecision {
        self.maybe_reset(now);
        *self.ip_requests.entry(ip).or_insert(0) += 1;

        let next_global = self.global_bytes.saturating_add(bytes);
        if next_global > self.global_bytes_limit {
            *self.ip_rejected_bytes.entry(ip).or_insert(0) += bytes;
            return RateLimitDecision::RejectedGlobal;
        }

        let current_ip = self.ip_bytes.get(&ip).copied().unwrap_or(0);
        let next_ip = current_ip.saturating_add(bytes);
        if next_ip > self.per_ip_bytes_limit {
            *self.ip_rejected_bytes.entry(ip).or_insert(0) += bytes;
            return RateLimitDecision::RejectedPerIp;
        }

        self.ip_bytes.insert(ip, next_ip);
        self.global_bytes = next_global;

        if let Some(alert) = self.alert_config {
            let threshold = (self.per_ip_bytes_limit as f64) * alert.bucket_limit_mult_threshold;
            if (next_ip as f64) >= threshold {
                *self.ip_alerts.entry(ip).or_insert(0) += 1;
                return RateLimitDecision::AllowedWithAlert;
            }
        }

        RateLimitDecision::Allowed
    }

    pub fn ip_bytes(&self, ip: IpAddr) -> u64 {
        self.ip_bytes.get(&ip).copied().unwrap_or(0)
    }

    pub fn ip_rejected_bytes(&self, ip: IpAddr) -> u64 {
        self.ip_rejected_bytes.get(&ip).copied().unwrap_or(0)
    }

    pub fn global_bytes(&self) -> u64 {
        self.global_bytes
    }
}
