//! Per-IP + global concurrency semaphore matching node #115
//! `net_utils/src/ip_semaphore.rs` (`0x4770f40..0x477165a`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Error returned when permit acquisition fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemaphoreError {
    GlobalExhausted,
    IpExhausted,
    Closed,
}

#[derive(Debug)]
struct Inner {
    global_available: usize,
    per_ip_limit: usize,
    closed: bool,
    per_ip_in_use: HashMap<IpAddr, usize>,
}

/// Two-level semaphore: acquires a global permit first, then a per-IP permit.
/// If per-IP acquisition fails, the global permit is immediately refunded
/// (matching `0x4770f70..0x4771061`).
#[derive(Clone, Debug)]
pub struct IpSemaphore {
    name: String,
    inner: Arc<Mutex<Inner>>,
}

/// RAII guard that releases both per-IP and global permits on drop.
#[derive(Debug)]
pub struct IpSemaphorePermit {
    ip: IpAddr,
    inner: Arc<Mutex<Inner>>,
}

impl Drop for IpSemaphorePermit {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.global_available = guard.global_available.saturating_add(1);
            if let Some(count) = guard.per_ip_in_use.get_mut(&self.ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    guard.per_ip_in_use.remove(&self.ip);
                }
            }
        }
    }
}

impl IpSemaphore {
    pub fn new(name: impl Into<String>, global_permits: usize, per_ip_limit: usize) -> Self {
        Self {
            name: format!("{}_ip_semaphore", name.into()),
            inner: Arc::new(Mutex::new(Inner {
                global_available: global_permits,
                per_ip_limit,
                closed: false,
                per_ip_in_use: HashMap::new(),
            })),
        }
    }

    pub fn metric_name(&self) -> &str {
        &self.name
    }

    pub fn try_acquire(&self, ip: IpAddr) -> Result<IpSemaphorePermit, SemaphoreError> {
        let mut guard = self.inner.lock().unwrap();
        if guard.closed {
            return Err(SemaphoreError::Closed);
        }
        if guard.global_available == 0 {
            return Err(SemaphoreError::GlobalExhausted);
        }
        let current = guard.per_ip_in_use.get(&ip).copied().unwrap_or(0);
        if current >= guard.per_ip_limit {
            return Err(SemaphoreError::IpExhausted);
        }
        guard.global_available -= 1;
        guard.per_ip_in_use.insert(ip, current + 1);
        Ok(IpSemaphorePermit {
            ip,
            inner: Arc::clone(&self.inner),
        })
    }

    pub fn close(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.closed = true;
    }

    pub fn global_available(&self) -> usize {
        self.inner.lock().unwrap().global_available
    }

    pub fn ip_in_use(&self, ip: IpAddr) -> usize {
        self.inner
            .lock()
            .unwrap()
            .per_ip_in_use
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }
}
