//! Profiled `RwLock`, bounded metered channel, and sleep-retry utility matching
//! node #115 `net_utils/src/{rw_lock,channel,async_sleep_retry}.rs`.

use std::collections::VecDeque;
use std::sync::{
    Arc, Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

// --- rw_lock.rs (`profiled_rw_lock/`, `blocked_writer/profiled_rw_lock/`) ---

/// Observed primary slow-lock threshold in node #115 `net_utils/src/rw_lock.rs`
/// (`0x56496fb -> .rodata 0x459038` = `0.05`s = `50` ms).
pub const SLOW_WRITE_THRESHOLD_MS: u64 = 50;

/// Observed secondary/critical slow-lock alert threshold in node #115 `net_utils/src/rw_lock.rs`
/// (`0x5649789 -> .rodata 0x458f50` = `0.35`s = `350` ms).
pub const CRITICAL_WRITE_THRESHOLD_MS: u64 = 350;

/// RwLock wrapper recording acquisition counts and max wait latency.
#[derive(Debug)]
pub struct ProfiledRwLock<T> {
    name: String,
    inner: RwLock<T>,
    read_acquisitions: AtomicU64,
    write_acquisitions: AtomicU64,
    blocked_writers: AtomicU64,
    slow_threshold: Duration,
}

impl<T> ProfiledRwLock<T> {
    pub fn new(name: impl Into<String>, value: T) -> Self {
        Self {
            name: format!("profiled_rw_lock/{}", name.into()),
            inner: RwLock::new(value),
            read_acquisitions: AtomicU64::new(0),
            write_acquisitions: AtomicU64::new(0),
            blocked_writers: AtomicU64::new(0),
            slow_threshold: Duration::from_millis(SLOW_WRITE_THRESHOLD_MS),
        }
    }

    pub fn metric_name(&self) -> &str {
        &self.name
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        self.read_acquisitions.fetch_add(1, Ordering::Relaxed);
        self.inner.read().expect("ProfiledRwLock poisoned on read")
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let start = Instant::now();
        let guard = self
            .inner
            .write()
            .expect("ProfiledRwLock poisoned on write");
        if start.elapsed() >= self.slow_threshold {
            self.blocked_writers.fetch_add(1, Ordering::Relaxed);
        }
        self.write_acquisitions.fetch_add(1, Ordering::Relaxed);
        guard
    }

    pub fn read_count(&self) -> u64 {
        self.read_acquisitions.load(Ordering::Relaxed)
    }

    pub fn write_count(&self) -> u64 {
        self.write_acquisitions.load(Ordering::Relaxed)
    }

    pub fn blocked_writer_count(&self) -> u64 {
        self.blocked_writers.load(Ordering::Relaxed)
    }
}

// --- channel.rs (`net_utils/src/channel.rs`) ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    Full,
    Empty,
    Closed,
}

#[derive(Debug)]
struct ChannelState<T> {
    queue: VecDeque<T>,
    capacity: usize,
    closed: bool,
    sent: u64,
    received: u64,
    dropped_full: u64,
}

/// Bounded multi-producer / multi-consumer channel with queue metrics.
#[derive(Debug)]
pub struct BoundedChannel<T> {
    name: String,
    state: Arc<(Mutex<ChannelState<T>>, Condvar)>,
}

impl<T> Clone for BoundedChannel<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

impl<T> BoundedChannel<T> {
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        Self {
            name: name.into(),
            state: Arc::new((
                Mutex::new(ChannelState {
                    queue: VecDeque::with_capacity(capacity.min(1024)),
                    capacity,
                    closed: false,
                    sent: 0,
                    received: 0,
                    dropped_full: 0,
                }),
                Condvar::new(),
            )),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn try_send(&self, item: T) -> Result<(), (ChannelError, T)> {
        let (lock, cvar) = &*self.state;
        let mut st = lock.lock().unwrap();
        if st.closed {
            return Err((ChannelError::Closed, item));
        }
        if st.queue.len() >= st.capacity {
            st.dropped_full += 1;
            return Err((ChannelError::Full, item));
        }
        st.queue.push_back(item);
        st.sent += 1;
        cvar.notify_one();
        Ok(())
    }

    pub fn try_recv(&self) -> Result<T, ChannelError> {
        let (lock, _) = &*self.state;
        let mut st = lock.lock().unwrap();
        if let Some(item) = st.queue.pop_front() {
            st.received += 1;
            return Ok(item);
        }
        if st.closed {
            Err(ChannelError::Closed)
        } else {
            Err(ChannelError::Empty)
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, ChannelError> {
        let (lock, cvar) = &*self.state;
        let mut st = lock.lock().unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(item) = st.queue.pop_front() {
                st.received += 1;
                return Ok(item);
            }
            if st.closed {
                return Err(ChannelError::Closed);
            }
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ChannelError::Empty);
            };
            let (next, res) = cvar.wait_timeout(st, rem).unwrap();
            st = next;
            if res.timed_out() && st.queue.is_empty() {
                return if st.closed {
                    Err(ChannelError::Closed)
                } else {
                    Err(ChannelError::Empty)
                };
            }
        }
    }

    pub fn close(&self) {
        let (lock, cvar) = &*self.state;
        let mut st = lock.lock().unwrap();
        st.closed = true;
        cvar.notify_all();
    }

    pub fn len(&self) -> usize {
        self.state.0.lock().unwrap().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        let st = self.state.0.lock().unwrap();
        (st.sent, st.received, st.dropped_full)
    }
}

// --- async_sleep_retry.rs (`async_sleep_retry retried `, `async_sleep_retry retries exhausted: `) ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_retries: usize,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryExhausted<E> {
    pub attempts: usize,
    pub last_error: E,
}

impl<E: core::fmt::Display> core::fmt::Display for RetryExhausted<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "async_sleep_retry retries exhausted: {}", self.last_error)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RetryExhausted<E> {}

/// Run `op` with bounded retries and exponential backoff (zero-sleep capable for tests).
pub fn sleep_retry<T, E, F>(policy: RetryPolicy, mut op: F) -> Result<(T, usize), RetryExhausted<E>>
where
    F: FnMut(usize) -> Result<T, E>,
{
    let mut backoff = policy.initial_backoff;
    let total_attempts = policy.max_retries.saturating_add(1);
    let mut last_err = None;
    for attempt in 0..total_attempts {
        match op(attempt) {
            Ok(v) => return Ok((v, attempt)),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < total_attempts && !backoff.is_zero() {
                    std::thread::sleep(backoff);
                    backoff = backoff.saturating_mul(2).min(policy.max_backoff);
                }
            }
        }
    }
    Err(RetryExhausted {
        attempts: total_attempts,
        last_error: last_err.expect("total_attempts >= 1"),
    })
}
