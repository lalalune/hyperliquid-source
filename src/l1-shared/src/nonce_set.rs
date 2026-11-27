//! Order-nonce admission ring and 19-address expanded window (`l1/src/nonce_set.rs`).
//!
//! Anchored to node #115 evidence packet `research/work-items/action-wire-nonce-admission-115`
//! (`0x4228080`, `0x4228310`, `0x421a3c0`, `0x421a520`, `0x450c430` — 29,600 cases, 0 mismatches).

use std::collections::{BTreeSet, VecDeque};

use crate::Address;

/// Default per-account nonce ring window (`100`).
pub const DEFAULT_WINDOW: usize = 100;

/// Expanded per-account nonce ring window (`400`) granted to [`EXPANDED_WINDOW_ADDRESSES`].
pub const EXPANDED_WINDOW: usize = 400;

/// Future nonce upper bound (`+86,400,000 ms` = +24h; `-120,000 ms` with `flag_b`).
pub const UPPER_BOUND_MS: u64 = 86_400_000;
pub const UPPER_BOUND_FLAG_B_DELTA_MS: u64 = 120_000;

/// Past nonce lower bound (`-172,800,000 ms` = -48h; `172,680,000 ms` with `flag_b`).
pub const LOWER_BOUND_MS: u64 = 172_800_000;
pub const LOWER_BOUND_FLAG_B_MS: u64 = 172_680_000;

/// Observed result tags in `0x4228080` and `action-wire-error-display-115`.
pub const TAG_OK: u16 = 0x1a2;
pub const TAG_TOO_MANY_PENDING: u16 = 0x61;
pub const TAG_NONCE_TOO_LOW: u16 = 0xcb;
pub const TAG_NONCE_TOO_HIGH: u16 = 0xcc;
pub const TAG_NONCE_DUPLICATE: u16 = 0xcd;

/// Exact 19 hardcoded 20-byte addresses receiving the 400-nonce window in `0x4228310`
/// (8 from `0x421a520` + 8 from `0x421a3c0` + 3 inline constants in `0x4228310`).
pub const EXPANDED_WINDOW_ADDRESSES: [Address; 19] = [
    // set-a (0x421a520)
    [0x01, 0x04, 0x61, 0xc1, 0x4e, 0x14, 0x6a, 0xc3, 0x5f, 0xe4, 0x22, 0x71, 0xbd, 0xc1, 0x13, 0x4e, 0xe3, 0x1c, 0x70, 0x3a],
    [0x07, 0xbe, 0xd5, 0xc0, 0x83, 0x06, 0xe0, 0x26, 0x79, 0x7e, 0x5e, 0xa9, 0x3c, 0x29, 0x3a, 0xbc, 0x56, 0x73, 0xc2, 0xad],
    [0x31, 0xca, 0x83, 0x95, 0xcf, 0x83, 0x7d, 0xe0, 0x8b, 0x24, 0xda, 0x3f, 0x66, 0x0e, 0x77, 0x76, 0x1d, 0xfb, 0x97, 0x4b],
    [0x76, 0x84, 0x84, 0xf7, 0xe2, 0xeb, 0xb6, 0x75, 0xc5, 0x78, 0x38, 0x36, 0x6c, 0x02, 0xae, 0x99, 0xba, 0x2a, 0x9b, 0x08],
    [0x93, 0xe2, 0x55, 0x1d, 0x82, 0x1d, 0xda, 0x10, 0x80, 0xa3, 0x72, 0xf0, 0xb0, 0x4b, 0x86, 0x46, 0x83, 0x20, 0x33, 0x3d],
    [0xa1, 0x50, 0x99, 0xa3, 0x0b, 0xbf, 0x2e, 0x68, 0x94, 0x2d, 0x6f, 0x4c, 0x43, 0xd7, 0x0d, 0x04, 0xfa, 0xea, 0xb0, 0xa0],
    [0xc6, 0x4c, 0xc0, 0x0b, 0x46, 0x10, 0x1b, 0xd4, 0x0a, 0xa1, 0xc3, 0x12, 0x11, 0x95, 0xe8, 0x5c, 0x0b, 0x09, 0x18, 0xd8],
    [0xdf, 0xc2, 0x4b, 0x07, 0x7b, 0xc1, 0x42, 0x5a, 0xd1, 0xde, 0xa7, 0x5b, 0xcb, 0x6f, 0x81, 0x58, 0xe1, 0x0d, 0xf3, 0x03],
    // set-b (0x421a3c0)
    [0x2e, 0x3d, 0x94, 0xf0, 0x56, 0x27, 0x03, 0xb2, 0x5c, 0x83, 0x30, 0x8a, 0x05, 0x04, 0x6d, 0xda, 0xf9, 0xa8, 0xdd, 0x14],
    [0x2e, 0xd5, 0xc4, 0x48, 0x4e, 0xa3, 0xff, 0x8b, 0x57, 0xd5, 0xf2, 0xfb, 0x15, 0x2a, 0x40, 0xd9, 0xf2, 0xb6, 0x83, 0x08],
    [0x4f, 0xbe, 0x63, 0x4d, 0x33, 0x28, 0xb1, 0xd5, 0x6f, 0x10, 0x5b, 0x88, 0x7e, 0xd2, 0x5d, 0xcb, 0x2c, 0x71, 0xb8, 0x8d],
    [0x5e, 0x17, 0x7e, 0x5e, 0x39, 0xc0, 0xf4, 0xe4, 0x21, 0xf5, 0x86, 0x5a, 0x6d, 0x8b, 0xee, 0xd8, 0xd9, 0x21, 0xcb, 0x70],
    [0x6a, 0x87, 0x50, 0xa4, 0xcc, 0xcf, 0xfd, 0xb3, 0x94, 0xa7, 0xbb, 0xe9, 0xd4, 0xd0, 0xdc, 0xef, 0x23, 0xfb, 0x14, 0x17],
    [0xb0, 0xa5, 0x5f, 0x13, 0xd2, 0x2f, 0x66, 0xe6, 0xd4, 0x95, 0xac, 0x98, 0x11, 0x38, 0x41, 0xb2, 0x32, 0x6e, 0x95, 0x40],
    [0xcb, 0xf4, 0xdf, 0xba, 0x8c, 0xdf, 0x95, 0x58, 0xe8, 0x15, 0x53, 0xb0, 0x8f, 0x0d, 0x7c, 0x91, 0x0b, 0x8c, 0x4e, 0x90],
    [0xd0, 0x76, 0x1c, 0x28, 0x19, 0x45, 0xec, 0x08, 0x4d, 0x32, 0x44, 0x15, 0xbb, 0x06, 0x06, 0xbe, 0x2c, 0x8d, 0xf3, 0x82],
    // wrapper-constant-1..3 (0x4228310)
    [0x67, 0x7d, 0x83, 0x1a, 0xef, 0x53, 0x28, 0x19, 0x08, 0x52, 0xe2, 0x4f, 0x13, 0xc4, 0x6c, 0xac, 0x05, 0xf9, 0x84, 0xe7],
    [0x3c, 0x83, 0xa5, 0xca, 0xe3, 0x2a, 0x05, 0xe8, 0x8c, 0xa6, 0xa0, 0x35, 0x0e, 0xdb, 0x54, 0x01, 0x94, 0x85, 0x1a, 0x76],
    [0x4d, 0xbf, 0x39, 0x4d, 0xa4, 0xb3, 0x48, 0xb8, 0x8e, 0x80, 0x90, 0xd2, 0x20, 0x51, 0xaf, 0x83, 0xe4, 0xcb, 0xae, 0xf4],
];

/// Returns `true` if `addr` is one of the 19 addresses granted the 400-nonce window.
pub fn has_expanded_window(addr: &Address) -> bool {
    EXPANDED_WINDOW_ADDRESSES.contains(addr)
}

/// Converts a Chrono-style `(year, ordinal_1based, seconds, nanos)` clock into
/// Unix milliseconds clamped at `0`, matching `0x4228080` rule 2.
pub fn clock_to_unix_millis(year: i32, ordinal: u32, seconds: u32, nanos: u32) -> u64 {
    let mut y = i64::from(year) - 1;
    let mut cycle_days = 0i64;
    if y < 0 {
        let cycles = (-y + 399) / 400;
        y += cycles * 400;
        cycle_days -= cycles * 146_097;
    }
    let days = i64::from(ordinal) + cycle_days + (y * 1461) / 4 - y / 100 + y / 400 - 719_163;
    let ms = (days * 86_400 + i64::from(seconds)) * 1_000 + i64::from(nanos / 1_000_000);
    ms.max(0) as u64
}

/// Nonce rejection reasons returned in exact `0x4228080` precedence order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceReject {
    /// Nonce is below `ring[len - limit]` (tag `0xcb`).
    BelowRingFloor { nonce: u64, floor: u64 },
    /// Nonce exceeds `now + upper_window` (tag `0xcc`).
    AboveUpperBound { nonce: u64, upper: u64 },
    /// Nonce is below `now - lower_window` (tag `0xcb`).
    BelowLowerBound { nonce: u64, lower: u64 },
    /// Nonce is already present in the sorted ring (tag `0xcd`).
    Duplicate { nonce: u64 },
    /// Evicting oldest entries would drop a nonce still in the pending set (tag `0x61`).
    TooManyPendingNonces,
}

impl NonceReject {
    pub const fn tag(self) -> u16 {
        match self {
            Self::BelowRingFloor { .. } | Self::BelowLowerBound { .. } => TAG_NONCE_TOO_LOW,
            Self::AboveUpperBound { .. } => TAG_NONCE_TOO_HIGH,
            Self::Duplicate { .. } => TAG_NONCE_DUPLICATE,
            Self::TooManyPendingNonces => TAG_TOO_MANY_PENDING,
        }
    }
}

/// Strictly ascending per-account nonce ring (`VecDeque<u64>`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NonceRing {
    ring: VecDeque<u64>,
}

impl NonceRing {
    pub fn new() -> Self {
        Self {
            ring: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.ring.iter().copied()
    }

    /// Checks a candidate nonce without mutating the ring (`0x4228080`).
    ///
    /// On success returns the sorted insertion index.
    pub fn check(
        &self,
        nonce: u64,
        now_ms: u64,
        expanded_window: bool,
        tight_bounds: bool,
        pending: Option<&BTreeSet<u64>>,
    ) -> Result<usize, NonceReject> {
        let limit = if expanded_window {
            EXPANDED_WINDOW
        } else {
            DEFAULT_WINDOW
        };

        // Rule 1: ring floor check.
        if self.ring.len() >= limit {
            let floor = self.ring[self.ring.len() - limit];
            if nonce < floor {
                return Err(NonceReject::BelowRingFloor { nonce, floor });
            }
        }

        // Rule 3: upper time bound.
        let upper = now_ms.saturating_add(if tight_bounds {
            UPPER_BOUND_MS - UPPER_BOUND_FLAG_B_DELTA_MS
        } else {
            UPPER_BOUND_MS
        });
        if nonce > upper {
            return Err(NonceReject::AboveUpperBound { nonce, upper });
        }

        // Rule 4: lower time bound.
        let lower_delta = if tight_bounds {
            LOWER_BOUND_FLAG_B_MS
        } else {
            LOWER_BOUND_MS
        };
        let lower = now_ms.saturating_sub(lower_delta);
        if nonce < lower {
            return Err(NonceReject::BelowLowerBound { nonce, lower });
        }

        // Rule 5: binary search for duplicate / insertion slot.
        let pos = match self.ring.binary_search(&nonce) {
            Ok(_) => return Err(NonceReject::Duplicate { nonce }),
            Err(idx) => idx,
        };

        // Rules 6 & 7: eviction fold against pending container when ring will overflow `limit`.
        if let Some(pend) = pending {
            if self.ring.len() + 1 > limit {
                let evict_count = self.ring.len() + 1 - limit;
                for i in 0..evict_count {
                    if pend.contains(&self.ring[i]) {
                        return Err(NonceReject::TooManyPendingNonces);
                    }
                }
            }
        }

        Ok(pos)
    }

    /// Runs the wrapper `0x4228310`: selects 400 vs 100 window from `signer`,
    /// checks the nonce, inserts in sorted order, and trims oldest entries to window.
    pub fn admit(
        &mut self,
        signer: &Address,
        nonce: u64,
        now_ms: u64,
        pending: Option<&BTreeSet<u64>>,
    ) -> Result<usize, NonceReject> {
        let expanded = has_expanded_window(signer);
        let pos = self.check(nonce, now_ms, expanded, false, pending)?;
        self.ring.insert(pos, nonce);
        let limit = if expanded {
            EXPANDED_WINDOW
        } else {
            DEFAULT_WINDOW
        };
        while self.ring.len() > limit {
            self.ring.pop_front();
        }
        Ok(pos)
    }
}
