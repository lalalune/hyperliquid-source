//! Retained request-row operation recovered from node94 `0x44b8050`.
//!
//! Evidence: `RE-008-request-throttle-94`. This owns only tag-one request keys;
//! it is separate from block admission's tag-zero request-removal context.
//! Logging, locks, allocation failures, pruning and network effects are outside
//! the conditional native value relation. See the packet's CONTRACT and PROOF.

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

/// Raw canonical-calendar candidate. Public fields also permit InvalidTime input.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestTimestamp {
    pub packed_date: i32,
    pub second: u32,
    pub nano: u32,
}

impl RequestTimestamp {
    /// Admit the captured canonical subset, excluding leap-second encodings.
    pub fn is_valid(self) -> bool {
        let year = i64::from(self.packed_date >> 13);
        let ordinal = (self.packed_date >> 4) & 511;
        (-262_143..=262_142).contains(&year)
            && (1..=365 + i32::from(leap(year))).contains(&ordinal)
            && self.packed_date & 15 == year_flag(year)
            && self.second < 86_400
            && self.nano < 1_000_000_000
    }

    fn ticks(self) -> i128 {
        let day = days_before_year(i64::from(self.packed_date >> 13))
            + i64::from((self.packed_date >> 4) & 511)
            - 1;
        (i128::from(day) * 86_400 + i128::from(self.second)) * 1_000_000_000 + i128::from(self.nano)
    }
}

/// Unsigned round followed by lexicographic bytes, with an implicit native tag1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestKey {
    pub round: u64,
    pub hash: [u8; 32],
}

/// Owned state values; no native padding, pointers, capacities or raw ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestRow {
    pub key: RequestKey,
    pub stamp: RequestTimestamp,
    pub reasons: BTreeSet<u8>,
    pub sent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialStateError {
    InvalidTime,
    DuplicateKey,
}

/// Registration and deadline are derived observations, not extra native fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThrottleOutcome {
    /// New safe policy: the complete state is unchanged.
    InvalidTime,
    /// New safe policy: registration and reason insertion remain; sent is kept.
    DeadlineRange { registered: bool },
    Held {
        registered: bool,
        deadline: RequestTimestamp,
    },
    Request {
        registered: bool,
        deadline: RequestTimestamp,
        key: RequestKey,
    },
}

/// A finite supplied-state map. Ordinary Rust allocation must succeed.
///
/// No rollback, native allocator identity or recovery from allocation panic is
/// promised. Snapshots clone values and do not expose mutable map references.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestThrottle {
    rows: BTreeMap<RequestKey, RequestRow>,
}

impl RequestThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reject invalid stamps and duplicate keys; no partially built state escapes.
    pub fn from_rows(
        rows: impl IntoIterator<Item = RequestRow>,
    ) -> Result<Self, InitialStateError> {
        let mut state = Self::new();
        for row in rows {
            if !row.stamp.is_valid() {
                return Err(InitialStateError::InvalidTime);
            }
            match state.rows.entry(row.key) {
                Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                Entry::Occupied(_) => return Err(InitialStateError::DuplicateKey),
            }
        }
        Ok(state)
    }

    /// Values are ordered by unsigned round and then the complete hash bytes.
    pub fn snapshot(&self) -> Vec<RequestRow> {
        self.rows.values().cloned().collect()
    }

    /// Apply one event, retaining the original stamp and every observed reason.
    ///
    /// `None` means exactly one second. `Some` supplies raw binary64 delay bits;
    /// integer arithmetic implements the frozen rounding/overflow relation.
    pub fn consider(
        &mut self,
        key: RequestKey,
        time: RequestTimestamp,
        reason: u8,
        delay_bits: Option<u64>,
    ) -> ThrottleOutcome {
        if !time.is_valid() {
            return ThrottleOutcome::InvalidTime;
        }
        let (row, registered) = match self.rows.entry(key) {
            Entry::Occupied(entry) => (entry.into_mut(), false),
            Entry::Vacant(entry) => (
                entry.insert(RequestRow {
                    key,
                    stamp: time,
                    reasons: BTreeSet::new(),
                    sent: false,
                }),
                true,
            ),
        };
        row.reasons.insert(reason);
        let nanos = delay_bits.map_or(1_000_000_000, delay_nanoseconds);
        let Some(deadline) = add_nanoseconds(row.stamp, nanos) else {
            return ThrottleOutcome::DeadlineRange { registered };
        };
        if time < deadline || row.sent {
            ThrottleOutcome::Held {
                registered,
                deadline,
            }
        } else {
            row.sent = true;
            ThrottleOutcome::Request {
                registered,
                deadline,
                key,
            }
        }
    }
}

// At most83 product bits. Round once to binary64 precision before conversion;
// finite input product overflow belongs to the nonfinite-to-zero class.
fn delay_nanoseconds(bits: u64) -> i64 {
    let exponent = ((bits >> 52) & 2047) as i32;
    if exponent == 2047 {
        return 0;
    }
    let fraction = bits & ((1_u64 << 52) - 1);
    let significand = if exponent == 0 {
        fraction
    } else {
        fraction | (1_u64 << 52)
    };
    let product = u128::from(significand) * 1_000_000_000;
    if product == 0 {
        return 0;
    }
    let width = 128 - product.leading_zeros();
    let shift = width.saturating_sub(53);
    let mut rounded = product >> shift;
    let mut power = if exponent == 0 {
        -1074
    } else {
        exponent - 1075
    } + shift as i32;
    if shift != 0 {
        let discarded = product & ((1_u128 << shift) - 1);
        let halfway = 1_u128 << (shift - 1);
        if discarded > halfway || (discarded == halfway && rounded & 1 == 1) {
            rounded += 1;
        }
        if rounded == 1_u128 << 53 {
            rounded >>= 1;
            power += 1;
        }
    }
    let top_power = power + (127 - rounded.leading_zeros()) as i32;
    if top_power > 1023 {
        return 0;
    }
    let negative = bits >> 63 != 0;
    if top_power >= 63 {
        return if negative { i64::MIN } else { i64::MAX };
    }
    let magnitude = if power >= 0 {
        rounded << power
    } else {
        rounded.checked_shr((-power) as u32).unwrap_or(0)
    } as i64;
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

fn leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn days_before_year(year: i64) -> i64 {
    365 * year + (year + 3).div_euclid(4) - (year + 99).div_euclid(100)
        + (year + 399).div_euclid(400)
}

fn year_flag(year: i64) -> i32 {
    ((days_before_year(year) + 3).rem_euclid(7) + 1) as i32 + if leap(year) { 0 } else { 8 }
}

fn add_nanoseconds(stamp: RequestTimestamp, nanos: i64) -> Option<RequestTimestamp> {
    let total = stamp.ticks() + i128::from(nanos);
    let day = total.div_euclid(86_400_000_000_000) as i64;
    if day < days_before_year(-262_143) || day >= days_before_year(262_143) {
        return None;
    }
    let (mut low, mut high) = (-262_143_i64, 262_143_i64);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if days_before_year(middle) <= day {
            low = middle;
        } else {
            high = middle;
        }
    }
    let ordinal = day - days_before_year(low) + 1;
    let remainder = total.rem_euclid(86_400_000_000_000);
    Some(RequestTimestamp {
        packed_date: ((low as i32) << 13) | ((ordinal as i32) << 4) | year_flag(low),
        second: (remainder / 1_000_000_000) as u32,
        nano: (remainder % 1_000_000_000) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_delay_covers_nonfinite_overflow_and_saturation() {
        for bits in [
            0,
            1,
            0x8000_0000_0000_0001,
            0x7ff0_0000_0000_0000,
            0xfff0_0000_0000_0000,
            0x7ff0_0000_0000_0001,
            0x7fef_ffff_ffff_ffff,
        ] {
            assert_eq!(delay_nanoseconds(bits), 0);
        }
        assert_eq!(delay_nanoseconds(0x3ff0_0000_0000_0000), 1_000_000_000);
        assert_eq!(delay_nanoseconds(0xbff0_0000_0000_0000), -1_000_000_000);
        assert_eq!(delay_nanoseconds(0x4210_0000_0000_0000), i64::MAX);
        assert_eq!(delay_nanoseconds(0xc210_0000_0000_0000), i64::MIN);
        assert_eq!(delay_nanoseconds(0x3fc3_3333_3333_3333), 150_000_000);
    }

    #[test]
    fn calendar_bridge_handles_negative_century_and_borrow() {
        let stamp = RequestTimestamp {
            packed_date: (-100 << 13) | 16 | year_flag(-100),
            second: 0,
            nano: 0,
        };
        assert!(stamp.is_valid());
        let before = add_nanoseconds(stamp, -1).unwrap();
        assert_eq!(before.packed_date >> 13, -101);
        assert_eq!((before.packed_date >> 4) & 511, 365);
        assert_eq!((before.second, before.nano), (86_399, 999_999_999));
        assert_eq!(add_nanoseconds(before, 1), Some(stamp));
    }
}
