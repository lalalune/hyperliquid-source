//! Asset and Perp DEX Index (`Pdi`) identifiers grounded in node #115.
//!
//! Binary evidence:
//! - `0x22b3160` (`l1/src/asset/pdi.rs:32`): encodes `perp_id = pdi * 10_000 + local_index`
//!   using checked multiply (`mulq $0x2710; jo`) and checked add (`add; cmp; jb`).
//! - `0x22e4810` (`l1/src/perp_meta.rs:163`): decodes `pdi = perp_id / 10_000`
//!   (reciprocal mul `0x346dc5d63886594b >> 11`) and `local = perp_id - pdi * 10_000`.
//! - `0x5911890` (`l1/src/book/book/impl_insert_order.rs`): order side byte at `+0xd2`
//!   is `0` vs nonzero (`Ask` vs `Bid` key-negation polarity).

/// Stride between Perp DEX Index (PDI) namespaces in node #115 (`0x2710` = 10,000).
pub const PDI_STRIDE: u64 = 10_000;

/// Perp DEX Index (`Pdi`). `Pdi(0)` is the main clearinghouse DEX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pdi(pub u64);

/// Globally encoded perpetual asset identifier (`pdi * 10_000 + local_index`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PerpAsset(pub u64);

/// Spot market pair index into `SpotMeta::universe`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpotAsset(pub u64);

/// Spot token index into `SpotMeta::tokens`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(pub u64);

/// Book / order side matching the `#115` byte polarity observed at order `+0xd2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Side {
    Bid = 0,
    Ask = 1,
}

impl Side {
    /// Convert a raw side byte using `#115` polarity (`0` -> `Bid`, nonzero -> `Ask`).
    #[inline]
    pub const fn from_raw_byte(raw: u8) -> Self {
        if raw == 0 {
            Self::Bid
        } else {
            Self::Ask
        }
    }

    #[inline]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Bid => Self::Ask,
            Self::Ask => Self::Bid,
        }
    }

    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Signed key transform observed in `#115` `0x5911890` (`book/impl_insert_order.rs`):
    /// negates the price key when side byte is `0` (`Bid`), keeps positive when nonzero (`Ask`).
    #[inline]
    pub const fn signed_price_key(self, raw_px: u64) -> i64 {
        let px = raw_px as i64;
        match self {
            Self::Bid => px.wrapping_neg(),
            Self::Ask => px,
        }
    }
}

impl Pdi {
    pub const FIRST: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Checked `pdi * 10_000 + local_index` matching `#115` `0x22b31f0..0x22b3207`.
    /// Note that `local_index` is not restricted to `< 10_000` by the raw arithmetic loop
    /// at `0x22b31f0`, so `perp_checked` checks only u64 overflow while `perp_in_namespace`
    /// additionally enforces `local_index < PDI_STRIDE`.
    #[inline]
    pub const fn perp_checked(self, local_index: u64) -> Option<PerpAsset> {
        let Some(base) = self.0.checked_mul(PDI_STRIDE) else {
            return None;
        };
        let Some(id) = base.checked_add(local_index) else {
            return None;
        };
        Some(PerpAsset(id))
    }

    /// Strict namespace-bounded perp constructor (`local_index < 10_000`).
    #[inline]
    pub const fn perp_in_namespace(self, local_index: u64) -> Option<PerpAsset> {
        if local_index >= PDI_STRIDE {
            return None;
        }
        self.perp_checked(local_index)
    }

    /// Materializes `[pdi * 10_000 + start .. pdi * 10_000 + end)` matching `#115` `0x22b3160`.
    /// Returns `Ok(Vec::new())` when `start >= end`; returns `None` on multiplication or addition overflow.
    pub fn perp_range(self, start: u64, end: u64) -> Option<Vec<PerpAsset>> {
        if start >= end {
            return Some(Vec::new());
        }
        let len = usize::try_from(end - start).ok()?;
        let mut out = Vec::with_capacity(len);
        for offset in 0..(end - start) {
            let base = self.0.checked_mul(PDI_STRIDE)?;
            let idx = start.checked_add(offset)?;
            let id = base.checked_add(idx)?;
            out.push(PerpAsset(id));
        }
        Some(out)
    }
}

impl PerpAsset {
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Split `perp_id` into `(Pdi, local_index)` via `/ 10_000` and `% 10_000`,
    /// matching `#115` `0x22e4832..0x22e4850`.
    #[inline]
    pub const fn split(self) -> (Pdi, u64) {
        (Pdi(self.0 / PDI_STRIDE), self.0 % PDI_STRIDE)
    }

    #[inline]
    pub const fn pdi(self) -> Pdi {
        Pdi(self.0 / PDI_STRIDE)
    }

    #[inline]
    pub const fn local_index(self) -> u64 {
        self.0 % PDI_STRIDE
    }
}
