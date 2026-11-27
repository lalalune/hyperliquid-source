//! Fixed-point quantity types (`Px`, `Sz`, `Szi`, `Ntl`, `Ntli`, `Wei`, `Usdc`)
//! grounded in node #115 `.text` and `.rodata`.
//!
//! Binary evidence:
//! - `.rodata` `0x5ed748`: 20-entry `f64` powers-of-ten table `10^0..=10^19`.
//! - `0x22e4888`: perp `sz_decimals` strict bound `< 7` (`MAX_PERP_SZ_DECIMALS = 6`).
//! - `node115-spot-decimal`: spot `sz_decimals` bound `<= 8` (`MAX_SPOT_SZ_DECIMALS = 8`).
//! - `0x294bcd0` / `0x29dfea0` (`qtys/impl_ntl.rs:682`), `0x22f0280` (`qtys/mod.rs:831,833`):
//!   unsigned saturating add reports carry through GOT slot `0x64e4ea8` and saturates to `u64::MAX`.
//! - `0x2a83960` (`qtys/impl_ntl.rs:683`): signed saturating add reports overflow through `0x64e4ea8`
//!   and saturates to `i64::MAX` or `i64::MIN` (`sar 63; xor 0x8000_0000_0000_0000; cmovo`).
//! - `0x25da200` / `0x58dfbc0` (`qtys/impl_sz.rs:9`): unsigned saturating sub reports borrow
//!   through `0x64e4ea8` and clamps to `0`.
//! - `0x22e642d` (`qtys/impl_wei.rs:6` + `qtys/mod.rs:835`): bounded hold addition checks
//!   `hold + delta` for both carry and `<= total`.
//! - `0x22f6d73..0x22f6dc8` (`qtys/mod.rs:848` + `qtys/impl_sz.rs:39`): signed position delta
//!   checks non-negative unsigned conversion (`test; js`), signed add overflow (`jo`), and sign-flip
//!   classification (`cmp` of sign classes `{neg: 1, zero: 2, pos: 0}`).

/// Exact 20-entry `f64` powers-of-10 table located at node #115 `.rodata` VA `0x5ed748`.
pub const POW10_F64: [f64; 20] = [
    1.0,
    10.0,
    100.0,
    1_000.0,
    10_000.0,
    100_000.0,
    1_000_000.0,
    10_000_000.0,
    100_000_000.0,
    1_000_000_000.0,
    10_000_000_000.0,
    100_000_000_000.0,
    1_000_000_000_000.0,
    10_000_000_000_000.0,
    100_000_000_000_000.0,
    1_000_000_000_000_000.0,
    1e16,
    1e17,
    1e18,
    1e19,
];

/// Maximum perp `sz_decimals` enforced at node #115 `0x22e4888` (`cmp $7, %rax; jae`).
pub const MAX_PERP_SZ_DECIMALS: u8 = 6;

/// Maximum spot `sz_decimals` enforced in node #115 spot decimal conversion (`<= 8`).
pub const MAX_SPOT_SZ_DECIMALS: u8 = 8;

/// USDC fixed-point scale (`10^6`).
pub const USDC_SCALE: u64 = 1_000_000;

/// Classification of arithmetic saturation events reported via node #115 slot `0x64e4ea8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverflowKind {
    UnsignedAdd,
    UnsignedSub,
    SignedAdd,
    SignedSub,
    UnsignedMul,
}

/// Sink for observing node #115 saturating overflow/underflow reports (`0x64e4ea8`).
pub trait OverflowSink {
    fn report(&mut self, kind: OverflowKind);
}

/// Default no-op sink when callers only need the saturated value.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopOverflowSink;

impl OverflowSink for NoopOverflowSink {
    #[inline]
    fn report(&mut self, _kind: OverflowKind) {}
}

/// Test/audit sink that records every overflow/underflow report in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordingOverflowSink {
    pub events: Vec<OverflowKind>,
}

impl OverflowSink for RecordingOverflowSink {
    #[inline]
    fn report(&mut self, kind: OverflowKind) {
        self.events.push(kind);
    }
}

#[inline]
fn sat_add_u64(a: u64, b: u64, sink: &mut impl OverflowSink) -> u64 {
    let (sum, carry) = a.overflowing_add(b);
    if carry {
        sink.report(OverflowKind::UnsignedAdd);
        u64::MAX
    } else {
        sum
    }
}

#[inline]
fn sat_sub_u64(a: u64, b: u64, sink: &mut impl OverflowSink) -> u64 {
    let (diff, borrow) = a.overflowing_sub(b);
    if borrow {
        sink.report(OverflowKind::UnsignedSub);
        0
    } else {
        diff
    }
}

/// Signed saturating addition matching node #115 `0x2a83a6d..0x2a83ab4`:
/// on overflow, reports via sink and returns `i64::MAX` when wrapped result is negative
/// (i.e. positive + positive) or `i64::MIN` when wrapped result is non-negative
/// (i.e. negative + negative).
#[inline]
fn sat_add_i64(a: i64, b: i64, sink: &mut impl OverflowSink) -> i64 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow {
        sink.report(OverflowKind::SignedAdd);
        if sum < 0 { i64::MAX } else { i64::MIN }
    } else {
        sum
    }
}

#[inline]
fn sat_sub_i64(a: i64, b: i64, sink: &mut impl OverflowSink) -> i64 {
    let (diff, overflow) = a.overflowing_sub(b);
    if overflow {
        sink.report(OverflowKind::SignedSub);
        if diff < 0 { i64::MAX } else { i64::MIN }
    } else {
        diff
    }
}

/// Fixed-point price (`Px`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Px(pub u64);

impl Px {
    #[inline]
    pub const fn new_nonzero(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Truncates raw price to 5 significant digits via `#115` `0x269d520`.
    #[inline]
    pub fn truncate_five_sig_figs(self) -> Self {
        Self(node115_five_significant_digits::truncate(self.0))
    }

    /// Checked `px * sz -> Ntl` (128-bit intermediate, returning `None` on overflow past `u64::MAX`).
    #[inline]
    pub fn checked_mul_sz(self, sz: Sz) -> Option<Ntl> {
        let prod = u128::from(self.0) * u128::from(sz.0);
        u64::try_from(prod).ok().map(Ntl)
    }

    /// Checked `px * sz -> Ntl` clamped below `i64::MAX` (`<= 0x7fff_ffff_ffff_fffe`) as observed in
    /// `#115` `fees-credit-caller-115` (`0x3c10000`).
    #[inline]
    pub fn mul_clamped_signed_max(self, multiplier: u64) -> u64 {
        let prod = u128::from(self.0) * u128::from(multiplier);
        if prod > 0x7fff_ffff_ffff_fffe {
            0
        } else {
            prod as u64
        }
    }
}

/// Unsigned fixed-point size (`Sz`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sz(pub u64);

impl Sz {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Saturating addition matching `#115` `qtys/mod.rs:831` (`0x58df360` / `0x22f0280`).
    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_u64(self.0, rhs.0, sink))
    }

    /// Saturating subtraction matching `#115` `qtys/impl_sz.rs:9` (`0x58dfbc0` / `0x25da200`).
    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_u64(self.0, rhs.0, sink))
    }

    /// Convert to signed `Szi`, rejecting values with bit 63 set (`>= 2^63`) as checked at `0x22f6d7a`.
    #[inline]
    pub const fn to_signed(self) -> Option<Szi> {
        if (self.0 as i64) < 0 {
            None
        } else {
            Some(Szi(self.0 as i64))
        }
    }
}

/// Signed fixed-point position size (`Szi`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Szi(pub i64);

impl Szi {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_i64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_i64(self.0, rhs.0, sink))
    }

    /// Sign class matching `#115` `0x22f6d94..0x22f6db8`:
    /// `0` for positive (`> 0`), `1` for negative (`< 0`), `2` for zero (`== 0`).
    #[inline]
    pub const fn sign_class(self) -> u8 {
        if self.0 > 0 {
            0
        } else if self.0 < 0 {
            1
        } else {
            2
        }
    }

    /// Returns true if transitioning from `self` to `next` crosses or exits a nonzero sign class,
    /// matching `#115` `0x22f6db3..0x22f6dc6` (nonzero `self` whose sign class differs from `next`).
    #[inline]
    pub const fn sign_changed_from_nonzero(self, next: Self) -> bool {
        self.0 != 0 && self.sign_class() != next.sign_class()
    }

    #[inline]
    pub const fn abs_sz(self) -> Sz {
        Sz(self.0.unsigned_abs())
    }
}

/// Unsigned fixed-point notional (`Ntl`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ntl(pub u64);

impl Ntl {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Saturating addition matching `#115` `qtys/impl_ntl.rs:682` (`0x294bcd0` / `0x29dfea0`).
    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_u64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_u64(self.0, rhs.0, sink))
    }

    /// Unsigned division by `10_000` (exact reciprocal multiply `0x346dc5d63886594b >> 11`
    /// observed at `#115` `0x2a83a52`).
    #[inline]
    pub const fn div_10000(self) -> u64 {
        self.0 / 10_000
    }

    /// Unsigned division by `1_000_000` (exact reciprocal multiply `0x431bde82d7b634db >> 18`
    /// observed in `#115` `0x3c10000` fee tallies).
    #[inline]
    pub const fn div_1_000_000(self) -> u64 {
        self.0 / USDC_SCALE
    }

    #[inline]
    pub const fn to_signed(self) -> Option<Ntli> {
        if (self.0 as i64) < 0 {
            None
        } else {
            Some(Ntli(self.0 as i64))
        }
    }
}

/// Signed fixed-point notional (`Ntli`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ntli(pub i64);

impl Ntli {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Saturating addition matching `#115` `qtys/impl_ntl.rs:683` (`0x2a83a6d..0x2a83ab4`).
    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_i64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_i64(self.0, rhs.0, sink))
    }

    /// Checked negation matching `#115` `0x2a886a8` (`neg; jo`).
    #[inline]
    pub const fn checked_neg(self) -> Option<Self> {
        match self.0.checked_neg() {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Clamps negative values to `0`, matching `#115` `0x2a886d3..0x2a886db` (`cmovg`).
    #[inline]
    pub const fn clamp_non_negative(self) -> Ntl {
        if self.0 > 0 { Ntl(self.0 as u64) } else { Ntl(0) }
    }
}

/// Spot token wei balance (`Wei`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wei(pub u64);

impl Wei {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_u64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_u64(self.0, rhs.0, sink))
    }

    /// Checked hold increment against total balance, matching `#115` `0x22e642d..0x22e6440`
    /// (`hold + delta` must neither overflow `u64` nor exceed `total`).
    #[inline]
    pub const fn checked_hold_add(hold: Self, delta: Self, total: Self) -> Option<Self> {
        let Some(new_hold) = hold.0.checked_add(delta.0) else {
            return None;
        };
        if new_hold <= total.0 {
            Some(Self(new_hold))
        } else {
            None
        }
    }
}

/// Unsigned 6-decimal USDC fixed-point amount.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Usdc(pub u64);

impl Usdc {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_u64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_u64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn to_f64(self) -> f64 {
        (self.0 as f64) / POW10_F64[6]
    }
}

/// Signed 6-decimal USDC fixed-point amount.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsdcSigned(pub i64);

impl UsdcSigned {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn raw(self) -> i64 {
        self.0
    }

    #[inline]
    pub fn sat_add(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_add_i64(self.0, rhs.0, sink))
    }

    #[inline]
    pub fn sat_sub(self, rhs: Self, sink: &mut impl OverflowSink) -> Self {
        Self(sat_sub_i64(self.0, rhs.0, sink))
    }
}

/// Non-negative signed quantity scaling by `f64` with finite/range clamping, matching `#115`
/// `0x46a6aa0` (`l1/src/qtys/mod.rs:847:1`).
///
/// Exact `#115` semantics:
/// - `raw < 0` returns `None` (node #115 panics via `Result::unwrap()` at `qtys/mod.rs:847:1`),
/// - computes `prod = (raw as f64) * factor`,
/// - non-finite (`NaN`, `+inf`, `-inf`) yields `0`,
/// - finite values are clamped to `[-2^63, 2^63]` (`0xc3e0000000000000`..`0x43e0000000000000`),
/// - values `> 0x43dfffffffffffff` (`9223372036854774784.0`) saturate to `i64::MAX as u64`,
/// - values `<= 0.0` (or `NaN`) clamp to `0`,
/// - otherwise truncates toward zero as `u64`.
#[inline]
pub fn scale_nonneg_i64_by_f64_clamped(raw: i64, factor: f64) -> Option<u64> {
    if raw < 0 {
        return None;
    }
    let prod = (raw as f64) * factor;
    if !prod.is_finite() {
        return Some(0);
    }
    let lo = f64::from_bits(0xc3e0_0000_0000_0000); // -2^63
    let hi = f64::from_bits(0x43e0_0000_0000_0000); // +2^63
    let max_i64_f64 = f64::from_bits(0x43df_ffff_ffff_ffff); // 9223372036854774784.0
    let clamped = prod.clamp(lo, hi);
    if clamped.is_nan() || clamped <= 0.0 {
        Some(0)
    } else if clamped > max_i64_f64 {
        Some(i64::MAX as u64)
    } else {
        Some((clamped as i64) as u64)
    }
}
