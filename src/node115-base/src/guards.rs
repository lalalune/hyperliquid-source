//! Runtime guards and EMA tracker grounded in node #115 `base/src/{c_guard,singleton_set,ema_tracker}.rs`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Single-initialization guard mirroring `base/src/c_guard.rs` (`"CGuard was set too many times"`).
#[derive(Debug, Default)]
pub struct CGuard<T> {
    inner: OnceLock<T>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlreadySetError;

impl<T> CGuard<T> {
    pub const fn new() -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    pub fn try_set(&self, value: T) -> Result<(), AlreadySetError> {
        self.inner.set(value).map_err(|_| AlreadySetError)
    }

    pub fn set(&self, value: T) {
        if self.inner.set(value).is_err() {
            panic!("CGuard was set too many times");
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.inner.get()
    }
}

/// Unique-registration set mirroring `base/src/singleton_set.rs`
/// (`0x1560ab0..0x1560e2f`, `"SingletonSet could not register "`).
#[derive(Clone, Debug, Default)]
pub struct SingletonSet {
    names: BTreeSet<String>,
}

impl SingletonSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_register(&mut self, name: impl Into<String>) -> Result<(), String> {
        let key = name.into();
        if self.names.insert(key.clone()) {
            Ok(())
        } else {
            Err(format!("SingletonSet could not register {key}"))
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Exponential moving average tracker enforcing node #115 `base/src/ema_tracker.rs:58`
/// (`0x5a30130..0x5a305da`, `"assertion failed: self.denom > 0."`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EmaTracker {
    numer: f64,
    denom: f64,
    decay: f64,
}

impl EmaTracker {
    pub fn new(decay: f64) -> Self {
        assert!(decay.is_finite() && (0.0..=1.0).contains(&decay));
        Self {
            numer: 0.0,
            denom: 0.0,
            decay,
        }
    }

    pub fn update(&mut self, sample: f64, weight: f64) {
        assert!(sample.is_finite() && weight.is_finite() && weight > 0.0);
        self.numer = self.numer * self.decay + sample * weight;
        self.denom = self.denom * self.decay + weight;
    }

    pub fn try_value(&self) -> Option<f64> {
        if self.denom > 0.0 {
            Some(self.numer / self.denom)
        } else {
            None
        }
    }

    pub fn value(&self) -> f64 {
        assert!(self.denom > 0.0, "assertion failed: self.denom > 0.");
        self.numer / self.denom
    }

    pub fn denom(&self) -> f64 {
        self.denom
    }
}
