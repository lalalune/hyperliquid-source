//! Raw & scaled volume accounting (`l1/src/raw_vlm.rs:17`, `l1/src/scaled_vlm.rs:16`)
//! and open-order cap thresholds (`0x5495210`, `0x5495680`, `0x2a82220`) grounded in node #115.
//!
//! Binary evidence:
//! - `0x2a8b0a0` (576B FDE): folds `(raw_vlm, scaled_vlm)` across all perp DEX clearinghouses
//!   (`+0x50`, `+0x58`, stride `0x510`) and the spot clearinghouse (`+0x40`, `+0x48`), saturating
//!   at `u64::MAX` with overflow reports to `0x64e4ea8` (`0x6492e68` / `0x6483fe0`).
//! - `0x56195a0` (672B FDE): same cross-DEX + spot fold plus saturating add of an extra `raw_vlm`.
//! - `0x543dc50` (1200B FDE): folds `raw_vlm` across a slice of user records (stride `0x40`,
//!   user address at `+0x18..+0x2c`), saturating at `u64::MAX`.
//! - `0x5495210` / `0x5495680` (`fees-open-order-threshold-115`): open order cap is
//!   `1000 + min(scaled_vlm / 500_000_000, 4000)` or flat `10_000` for 8 `.rodata` addresses.

use crate::UserAddress;
use node115_assets::qtys::{OverflowKind, OverflowSink};

/// Base open-order limit for any user (`0x3e8` in `#115` `0x5495210`).
pub const BASE_OPEN_ORDER_CAP: u64 = 1_000;

/// Maximum volume-earned bonus open orders (`4000` -> max normal cap `5000`).
pub const MAX_BONUS_OPEN_ORDERS: u64 = 4_000;

/// Scaled volume per extra open-order slot (`500_000_000`).
pub const VOLUME_PER_EXTRA_ORDER: u64 = 500_000_000;

/// Flat open-order limit for the 8 privileged addresses (`10_000`).
pub const PRIVILEGED_OPEN_ORDER_CAP: u64 = 10_000;

/// Raw return-head tags observed in `#115` `0x5495210` / `0x5495680` and `0x2a82220`.
pub const OPEN_ORDER_PASS_HEAD: u64 = 0x8000_0000_0000_001b;
pub const OPEN_ORDER_REJECT_HEAD: u64 = 0x8000_0000_0000_0018;

/// Eight 20-byte addresses observed in `#115` `0x421a520` (`.rodata` `0x454410`, `0x454420`,
/// `0x456c10`, `0x450d30`, `0x4513d0`, `0x453d70`, `0x455be0`, `0x454100`).
pub const PRIVILEGED_OPEN_ORDER_ADDRESSES: [UserAddress; 8] = [
    [
        0x01, 0x04, 0x61, 0xc1, 0x4e, 0x14, 0x6a, 0xc3, 0x5f, 0xe4, 0x22, 0x71, 0xbd, 0xc1, 0x13,
        0x4e, 0xe3, 0x1c, 0x70, 0x3a,
    ],
    [
        0x31, 0xca, 0x83, 0x95, 0xcf, 0x83, 0x7d, 0xe0, 0x8b, 0x24, 0xda, 0x3f, 0x66, 0x0e, 0x77,
        0x76, 0x1d, 0xfb, 0x97, 0x4b,
    ],
    [
        0x76, 0x84, 0x84, 0xf7, 0xe2, 0xeb, 0xb6, 0x75, 0xc5, 0x78, 0x38, 0x36, 0x6c, 0x02, 0xae,
        0x99, 0xba, 0x2a, 0x9b, 0x08,
    ],
    [
        0xc6, 0x4c, 0xc0, 0x0b, 0x46, 0x10, 0x1b, 0xd4, 0x0a, 0xa1, 0xc3, 0x12, 0x11, 0x95, 0xe8,
        0x5c, 0x0b, 0x09, 0x18, 0xd8,
    ],
    [
        0x07, 0xbe, 0xd5, 0xc0, 0x83, 0x06, 0xe0, 0x26, 0x79, 0x7e, 0x5e, 0xa9, 0x3c, 0x29, 0x3a,
        0xbc, 0x56, 0x73, 0xc2, 0xad,
    ],
    [
        0x93, 0xe2, 0x55, 0x1d, 0x82, 0x1d, 0xda, 0x10, 0x80, 0xa3, 0x72, 0xf0, 0xb0, 0x4b, 0x86,
        0x46, 0x83, 0x20, 0x33, 0x3d,
    ],
    [
        0xa1, 0x50, 0x99, 0xa3, 0x0b, 0xbf, 0x2e, 0x68, 0x94, 0x2d, 0x6f, 0x4c, 0x43, 0xd7, 0x0d,
        0x04, 0xfa, 0xea, 0xb0, 0xa0,
    ],
    [
        0xdf, 0xc2, 0x4b, 0x07, 0x7b, 0xc1, 0x42, 0x5a, 0xd1, 0xde, 0xa7, 0x5b, 0xcb, 0x6f, 0x81,
        0x58, 0xe1, 0x0d, 0xf3, 0x03,
    ],
];

/// Raw user trading volume (`l1/src/raw_vlm.rs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawVlm(pub u64);

impl RawVlm {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        let (sum, carry) = self.0.overflowing_add(rhs.0);
        if carry {
            sink.report(OverflowKind::UnsignedAdd);
            Self(u64::MAX)
        } else {
            Self(sum)
        }
    }
}

/// Scaled user trading volume (`l1/src/scaled_vlm.rs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScaledVlm(pub u64);

impl ScaledVlm {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        let (sum, carry) = self.0.overflowing_add(rhs.0);
        if carry {
            sink.report(OverflowKind::UnsignedAdd);
            Self(u64::MAX)
        } else {
            Self(sum)
        }
    }
}

/// Combined `(RawVlm, ScaledVlm)` pair returned by `#115` `0x2a8b0a0`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserVolumeTotals {
    pub raw: RawVlm,
    pub scaled: ScaledVlm,
}

/// Fold a user's volume across all perp DEX clearinghouses plus the spot clearinghouse,
/// matching `#115` `0x2a8b0a0` (`raw_vlm.rs:17` + `scaled_vlm.rs:16`).
pub fn fold_user_volumes(
    perp_dex_volumes: &[UserVolumeTotals],
    spot_volume: UserVolumeTotals,
    sink: &mut impl OverflowSink,
) -> UserVolumeTotals {
    let mut raw = RawVlm::ZERO;
    let mut scaled = ScaledVlm::ZERO;
    for entry in perp_dex_volumes {
        raw = raw.sat_add(entry.raw, sink);
        scaled = scaled.sat_add(entry.scaled, sink);
    }
    raw = raw.sat_add(spot_volume.raw, sink);
    scaled = scaled.sat_add(spot_volume.scaled, sink);
    UserVolumeTotals { raw, scaled }
}

/// Fold `raw_vlm` across a batch of users (each with its perp DEX + spot volume entries),
/// matching `#115` `0x543dc50` / `0x56195a0`.
pub fn fold_users_raw_volume<'a, I>(
    initial: RawVlm,
    users: I,
    sink: &mut impl OverflowSink,
) -> RawVlm
where
    I: IntoIterator<Item = (&'a [UserVolumeTotals], UserVolumeTotals)>,
{
    let mut total = initial;
    for (perps, spot) in users {
        let user_totals = fold_user_volumes(perps, spot, sink);
        total = total.sat_add(user_totals.raw, sink);
    }
    total
}

/// Returns true when `user` is one of the 8 `#115` `.rodata` privileged addresses (`0x421a520`).
#[inline]
pub fn is_privileged_open_order_address(user: &UserAddress) -> bool {
    PRIVILEGED_OPEN_ORDER_ADDRESSES.contains(user)
}

/// Computes the `#115` open-order limit for `user` given their combined `scaled_volume`.
#[inline]
pub fn open_order_limit(user: &UserAddress, scaled_volume: ScaledVlm) -> u64 {
    if is_privileged_open_order_address(user) {
        PRIVILEGED_OPEN_ORDER_CAP
    } else {
        BASE_OPEN_ORDER_CAP + (scaled_volume.0 / VOLUME_PER_EXTRA_ORDER).min(MAX_BONUS_OPEN_ORDERS)
    }
}

/// Descriptor flags checked by `#115` `0x5495210` / `0x5495680` when `open_count >= 1000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenOrderDescriptor {
    /// Descriptor byte 1 (`object +0xb8` exempt flag, `object +0xa0` reject flag).
    KindOne {
        bypass_cap: bool,
        force_reject: bool,
    },
    /// Descriptor byte 2 (always rejects at/above 1000 unless all-ones key).
    KindTwo,
    /// Any other descriptor byte (`order +0x31` reduce/reject flag, `order +0x19` TIF/type tag).
    Other {
        flag_31: bool,
        tag_19: u8,
    },
}

/// Outcome of the `#115` open-order cap gate (`0x5495210` / `0x5495680`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenOrderDecision {
    Pass,
    Reject,
}

impl OpenOrderDecision {
    #[inline]
    pub const fn raw_head(self) -> u64 {
        match self {
            Self::Pass => OPEN_ORDER_PASS_HEAD,
            Self::Reject => OPEN_ORDER_REJECT_HEAD,
        }
    }
}

/// Exact `#115` open-order admission cap predicate (`0x5495210` / `0x5495680`).
pub fn check_open_order_cap(
    user: &UserAddress,
    open_count: u64,
    descriptor: OpenOrderDescriptor,
    perp_dex_volumes: &[UserVolumeTotals],
    spot_volume: UserVolumeTotals,
    sink: &mut impl OverflowSink,
) -> OpenOrderDecision {
    if open_count < BASE_OPEN_ORDER_CAP {
        return OpenOrderDecision::Pass;
    }
    if let OpenOrderDescriptor::KindOne { bypass_cap: true, .. } = descriptor {
        return OpenOrderDecision::Pass;
    }
    if *user == [0xff; 20] {
        return OpenOrderDecision::Pass;
    }
    match descriptor {
        OpenOrderDescriptor::KindTwo => return OpenOrderDecision::Reject,
        OpenOrderDescriptor::KindOne {
            force_reject: true, ..
        } => return OpenOrderDecision::Reject,
        OpenOrderDescriptor::Other { flag_31, tag_19 } if flag_31 || tag_19 != 2 => {
            return OpenOrderDecision::Reject;
        }
        _ => {}
    }

    let limit = if is_privileged_open_order_address(user) {
        PRIVILEGED_OPEN_ORDER_CAP
    } else {
        // Exact `#115` `0x5495210` step 3: sum perp (+0x50/+0x58) + spot (+0x40), reporting
        // overflow on spot (+0x48) as well, then use the summed raw/scaled threshold input.
        let totals = fold_user_volumes(perp_dex_volumes, spot_volume, sink);
        BASE_OPEN_ORDER_CAP + (totals.raw.0 / VOLUME_PER_EXTRA_ORDER).min(MAX_BONUS_OPEN_ORDERS)
    };
    if open_count < limit {
        OpenOrderDecision::Pass
    } else {
        OpenOrderDecision::Reject
    }
}
