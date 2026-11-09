//! Owned fee-trial state for node115, with a bounded real string parser.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};
use node115_daycount_date::node115_date_from_ce_days;
pub type Address = [u8; 20];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Date(i32);
impl Date {
    pub fn from_ce_days(days: i32) -> Option<Self> {
        (node115_date_from_ce_days(days) != 0).then_some(Self(days))
    }
    pub fn ce_days(self) -> i32 {
        self.0
    }
    fn add(self, n: i32) -> Option<Self> {
        Self::from_ce_days(self.0.checked_add(n)?)
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct Trial {
    pub active: [f64; 4],
    pub volume: f64,
    pub requested: [f64; 4],
    pub original: [f64; 4],
    pub end: Option<Date>,
    pub tail: f64,
}
#[derive(Clone, Debug, Default, PartialEq)]
pub struct User {
    pub custom: Option<Trial>,
    pub last_trial: Option<Date>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct State {
    pub disabled: u8,
    pub default_rates: [f64; 4],
    pub templates: Vec<[f64; 4]>,
    /// Native secondary rows: only their second value is compared.
    pub alternatives: Vec<[f64; 2]>,
    /// Native iteration order, not sorted by this implementation.
    pub discounts: Vec<[f64; 2]>,
    pub users: BTreeMap<Address, User>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Status(u16),
    /// Owned scope failure, not a native status or parser error claim.
    UnsupportedString {
        field: usize,
    },
    DateOverflow,
}

/// The native short decimal branch for optional sign, digits and optional dot.
/// At least one digit before the dot is required in this bounded domain.
/// Other native decimal forms and the floating-parser fallback are excluded.
pub fn short_decimal(text: &str) -> Option<f64> {
    if text.is_empty() || text.len() > 17 {
        return None;
    }
    let bytes = text.as_bytes();
    let (negative, start) = match bytes[0] {
        b'-' => (true, 1),
        b'+' => (false, 1),
        _ => (false, 0),
    };
    if start == bytes.len() {
        return None;
    }
    let mut n = 0u64;
    let mut scale = 0u32;
    let mut dot = false;
    let mut digits = 0;
    for &c in &bytes[start..] {
        if c == b'.' && !dot && digits > 0 {
            dot = true;
            continue;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + u64::from(c - b'0');
        digits += 1;
        if dot {
            scale += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    let magnitude = if scale == 0 {
        n as f64
    } else {
        let denominator = 10u64.pow(scale);
        let fraction = (n % denominator) as f64 / denominator as f64;
        let integer = (n / denominator) as f64;
        if fraction == 0.0 {
            integer
        } else {
            // Native scales <=16 have exact binary64 powers of ten.
            let power = denominator as f64;
            let scaled = (integer + fraction) * power;
            let truncated = scaled as u64;
            let rounded = truncated + u64::from(scaled - truncated as f64 >= 0.5);
            rounded as f64 / power
        }
    };
    // Short native parsing normalizes all zero coefficients to positive zero.
    Some(if negative && n != 0 {
        -magnitude
    } else {
        magnitude
    })
}
fn minimum(base: f64, adjusted: f64) -> f64 {
    if adjusted.is_nan() || base < adjusted {
        base
    } else {
        adjusted
    }
}

/// `fees` uses native converter output order, corresponding to input string
/// offsets +0x18, +0x00, +0x48, +0x30. Affiliates are actual owned account keys
/// in caller-supplied order; duplicates and the caller key are retained.
pub fn start(
    state: &mut State,
    user: Address,
    now: Date,
    fees: [&str; 4],
    affiliates: &[Address],
) -> Outcome {
    let special = user == [0xff; 20] || user == [0xfe; 20];
    let (original, volume, tail, active) = if special {
        ([0.0; 4], 0.0, 0.0, false)
    } else {
        match state.users.get(&user).and_then(|u| u.custom.as_ref()) {
            Some(t) => (t.active, t.volume, t.tail, t.end.is_some()),
            None => (state.default_rates, 0.0, 1.0, false),
        }
    };
    if state.disabled != 0 || active {
        return Outcome::Status(0x149 + 4 * u16::from(state.disabled));
    }
    let mut requested = [0.0; 4];
    for (field, text) in fees.iter().enumerate() {
        if text.len() > 100 {
            return Outcome::Status(0x158);
        }
        let Some(value) = short_decimal(text) else {
            return Outcome::UnsupportedString { field };
        };
        requested[field] = value;
    }
    let mut exact = false;
    let mut prefix = false;
    for t in &state.templates {
        if t[0] == requested[0] && t[2] == requested[2] {
            prefix = true;
            if t[1] == requested[1] && t[3] == requested[3] {
                exact = true;
                break;
            }
        }
    }
    if !(exact
        || prefix
            && state
                .alternatives
                .iter()
                .any(|t| t[1] == requested[1] && t[1] == requested[3]))
    {
        return Outcome::Status(0x14a);
    }
    if let Some(last) = state.users.get(&user).and_then(|u| u.last_trial) {
        let Some(limit) = last.add(90) else {
            return Outcome::DateOverflow;
        };
        if limit.0 > now.0 {
            return Outcome::Status(0x14c);
        }
    }
    let Some(end) = now.add(14) else {
        return Outcome::DateOverflow;
    };
    let mut discount = 0.0;
    for row in &state.discounts {
        if row[0] > volume {
            break;
        }
        discount = row[1];
    }
    let factor = 1.0 - discount;
    let adjusted = requested.map(|v| if v > 0.0 { v * factor } else { v });
    if !(0..4).any(|i| original[i] - adjusted[i] > 0.0) {
        return Outcome::Status(0x14b);
    }
    let trial = Trial {
        active: core::array::from_fn(|i| minimum(original[i], adjusted[i])),
        volume,
        requested,
        original,
        end: Some(end),
        tail,
    };
    for key in affiliates.iter().chain(core::iter::once(&user)) {
        state.users.entry(*key).or_default().custom = Some(trial.clone());
    }
    Outcome::Status(0x1a2)
}
