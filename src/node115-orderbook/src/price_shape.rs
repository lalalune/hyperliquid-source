//! Order price shaping, tick-grid snapping, min/max notional checks, and price-band ratio gate
//! grounded in node #115 `0x5a21510` / `0x5a21ed0` / `0x2d3a160` (`RE-006-order-price-shape-115`).
//!
//! Binary evidence:
//! - Three identical-semantics copies: `0x5a21510..0x5a21ed0` (2,496 B), `0x5a21ed0..0x5a22890`
//!   (2,496 B), `0x2d3a160..0x2d3ab3b` (2,523 B).
//! - `.rodata` float constants: `1.1` (`0x459400`), `0.9` (`0x459788`), `100_000.0` (`0x459510`),
//!   `-100_000.0` (`0x458f20`), `1_000_000.0` (`0x4599a0`), `100.0` (`0x459498`).
//! - `.rodata` system-user exemptions: `[0xff; 20]` (`0x93e30b`) & `[0xee; 20]` (`0x93eb11`).
//! - Exact refusal status words: `0x19c` (`UserBlocked`), `0xde` (`InvalidMovedRef`),
//!   `0x6d` (`MaxNotionalExceeded`), `0x6c` (`InsufficientAvailable`), `0xc8` (`MinNotional`),
//!   `0x78` (`RateLimited`), `0x63` (`PriceBandExceeded`).

use node115_assets::pdi::Side;
use node115_assets::qtys::{Px, Sz};
use node115_fees::UserAddress;
use node115_mid_market_order_builder::tick_size_with_cap;

/// Bid limit slippage multiplier (`0x459400`).
pub const BID_SLIPPAGE_FACTOR: f64 = 1.1;

/// Ask limit slippage multiplier (`0x459788`).
pub const ASK_SLIPPAGE_FACTOR: f64 = 0.9;

/// Fraction move divisor (`0x459510` / `-100_000.0` at `0x458f20`).
pub const FRACTION_MOVE_DIVISOR: f64 = 100_000.0;

/// Maximum `max(mark, limit, ref') * sz` notional product (`0x1999_9999_9999_9999`, status `0x6d`).
pub const MAX_SHAPED_NOTIONAL_CAP: u64 = 0x1999_9999_9999_9999;

/// Minimum order notional threshold (`> 9_999_999`, i.e. `>= 10_000_000` = `$10.00`, status `0xc8`).
pub const MIN_ORDER_NOTIONAL_THRESHOLD: u64 = 9_999_999;

/// Maximum product cap before min-notional check (`0x7fff_ffff_ffff_fffe`).
pub const MAX_SIGNED_NOTIONAL_PRODUCT: u64 = 0x7fff_ffff_ffff_fffe;

/// System user A exempt from `$10` min-notional check (`0x93e30b`).
pub const SYSTEM_USER_FF: UserAddress = [0xff; 20];

/// System user B exempt from `$10` min-notional check (`0x93eb11`).
pub const SYSTEM_USER_EE: UserAddress = [0xee; 20];

/// Move specification for `shape_order_price` (step 5 of `0x5a21510`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriceMove {
    /// Add (Bid) or subtract (Ask) an absolute tick-scaled offset.
    ByAmount(u64),
    /// Scale reference by `1.0 + amount / (+100_000.0)` (Bid) or `1.0 + amount / (-100_000.0)` (Ask).
    ByFraction(u64),
}

/// Request inputs to node #115 `0x5a21510`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceShapeRequest {
    pub user: UserAddress,
    pub side: Side,
    pub sz: Sz,
    pub optional_ref: Option<Px>,
    pub price_move: PriceMove,
}

/// Market & risk context supplied to `shape_order_price` (steps 1..11 of `0x5a21510`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PriceShapeContext {
    pub user_blocked: bool,
    pub mark_px: Px,
    /// Market tick cap in raw price units: 10^(6 - size decimals). A tick already
    /// computed for the same pre-grid price also gives the native step.
    pub tick: u64,
    pub available_notional: u64,
    /// When `true`, skips the `$10` min-notional check (step 9 gate == 1, e.g. reduce-only).
    pub skip_min_notional: bool,
    /// Optional book top-of-book reference `(q0_ask_floor, q1_bid_ceil)` for step 9.
    pub book_ref_pxs: (u64, u64),
    pub rate_limited: bool,
    pub now_ms: u64,
    pub last_alert_ms: u64,
    pub band_exempt: bool,
    pub band_p: f64,
}

/// Accepted shaped order price output (step 12 of `0x5a21510`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShapedOrderPrice {
    pub limit_px: Px,
    pub shaped_ref_px: Px,
    pub stop_px: Option<Px>,
    pub sz: Sz,
}

/// Exact `#115` `0x5a21510` refusal variants with their native status words.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PriceShapeError {
    /// Status `0x19c`.
    UserBlocked,
    /// Status `0xde`.
    InvalidMovedRef,
    /// Status `0x6d`.
    MaxNotionalExceeded,
    /// Status `0x6c`.
    InsufficientAvailable { available_usd: f64 },
    /// Status `0xc8`.
    MinNotional { min_usd: f64 },
    /// Status `0x78`.
    RateLimited { should_alert: bool },
    /// Status `0x63`.
    PriceBandExceeded { band_pct: f64 },
}

impl PriceShapeError {
    /// Exact node #115 status word at `out + 0x10`.
    pub const fn status_word(self) -> u16 {
        match self {
            Self::UserBlocked => 0x19c,
            Self::InvalidMovedRef => 0xde,
            Self::MaxNotionalExceeded => 0x6d,
            Self::InsufficientAvailable { .. } => 0x6c,
            Self::MinNotional { .. } => 0xc8,
            Self::RateLimited { .. } => 0x78,
            Self::PriceBandExceeded { .. } => 0x63,
        }
    }
}

/// Exact `#115` `0x5a21510` float-to-u64 cast chain:
/// NaN / negative / non-finite -> `0`; values `>= 2^64` -> `u64::MAX`; clamped to `>= 1`.
#[inline]
fn cast_f64_to_u64_min1(v: f64) -> u64 {
    if !v.is_finite() || v <= 0.0 {
        return 1;
    }
    let two_pow_64 = f64::from_bits(0x43f0_0000_0000_0000);
    if v >= two_pow_64 {
        u64::MAX
    } else {
        (v as u64).max(1)
    }
}

/// Exact `#115` `0x5a21510` step 1..12 order price shaping pipeline.
pub fn shape_order_price(
    req: PriceShapeRequest,
    ctx: PriceShapeContext,
) -> Result<ShapedOrderPrice, PriceShapeError> {
    // Step 1: user block check (`0x19c`).
    if ctx.user_blocked {
        return Err(PriceShapeError::UserBlocked);
    }

    let is_ask = req.side == Side::Ask;
    let mark = ctx.mark_px.raw();

    // Step 4: reference & stop price choice.
    let raw_ref = req.optional_ref.map(Px::raw).filter(|&v| v != 0).unwrap_or(mark);
    let take_mark = raw_ref == mark || ((mark < raw_ref) ^ is_ask);
    let (chosen_ref, stop_px) = if take_mark {
        (mark, if mark == 0 { None } else { Some(Px(mark)) })
    } else {
        (raw_ref, None)
    };

    // Step 5: move by amount or by fraction (`0xde` on invalid amount move).
    let moved_ref = match req.price_move {
        PriceMove::ByAmount(amt) => {
            if is_ask {
                let diff = chosen_ref.checked_sub(amt).ok_or(PriceShapeError::InvalidMovedRef)?;
                if diff == 0 {
                    return Err(PriceShapeError::InvalidMovedRef);
                }
                diff
            } else {
                chosen_ref
                    .checked_add(amt)
                    .ok_or(PriceShapeError::InvalidMovedRef)?
            }
        }
        PriceMove::ByFraction(amt) => {
            let divisor = if is_ask {
                -FRACTION_MOVE_DIVISOR
            } else {
                FRACTION_MOVE_DIVISOR
            };
            let scaled = ((amt as f64) / divisor + 1.0) * (chosen_ref as f64);
            cast_f64_to_u64_min1(scaled.round())
        }
    };

    // Step 6: 1.1 (Bid) / 0.9 (Ask) limit factor + tick-grid snap (`q + 1` for Ask, `q` for Bid).
    let slip_factor = if is_ask {
        ASK_SLIPPAGE_FACTOR
    } else {
        BID_SLIPPAGE_FACTOR
    };
    let pre_grid = cast_f64_to_u64_min1(slip_factor * (moved_ref as f64));
    let tick = tick_size_with_cap(pre_grid, ctx.tick);
    let mut q = pre_grid / tick;
    if is_ask {
        q = q.saturating_add(1);
    }
    let limit_px = q.saturating_mul(tick).max(1);

    // Step 7: max notional cap (`0x6d`).
    let top = mark.max(limit_px).max(moved_ref);
    let top_notional = u128::from(top) * u128::from(req.sz.raw());
    if top_notional > u128::from(MAX_SHAPED_NOTIONAL_CAP) {
        return Err(PriceShapeError::MaxNotionalExceeded);
    }

    // Step 8: available notional check (`0x6c`).
    let limit_notional = u128::from(limit_px) * u128::from(req.sz.raw());
    if limit_notional > u128::from(ctx.available_notional) {
        return Err(PriceShapeError::InsufficientAvailable {
            available_usd: (ctx.available_notional as f64) / 1_000_000.0,
        });
    }

    // Step 9: $10 min-notional check (`0xc8`) with system-user `[0xff; 20]` / `[0xee; 20]` exemption.
    if !ctx.skip_min_notional {
        let (q0, q1) = ctx.book_ref_pxs;
        let chosen = if is_ask {
            if q0 != 0 { limit_px.max(q0) } else { limit_px }
        } else if q1 != 0 {
            limit_px.min(q1)
        } else {
            limit_px
        };
        let prod = u128::from(chosen) * u128::from(req.sz.raw());
        let is_system_user = req.user == SYSTEM_USER_FF || req.user == SYSTEM_USER_EE;
        if prod > u128::from(MAX_SIGNED_NOTIONAL_PRODUCT)
            || (prod <= u128::from(MIN_ORDER_NOTIONAL_THRESHOLD) && !is_system_user)
        {
            return Err(PriceShapeError::MinNotional { min_usd: 10.0 });
        }
    }

    // Step 10: rate-limit / time check (`0x78`).
    if ctx.rate_limited {
        let should_alert = ctx.now_ms >= ctx.last_alert_ms.saturating_add(5_000);
        return Err(PriceShapeError::RateLimited { should_alert });
    }

    // Step 11: price-band ratio gate (`0x63`).
    if !ctx.band_exempt {
        let r = (limit_px as f64) / (moved_ref as f64) - 1.0;
        let p = ctx.band_p;
        let ok = (p > r.abs())
            || (r > 0.0 && 1.0 > p && (1.0 / (1.0 - p) - 1.0) >= r);
        if !ok {
            return Err(PriceShapeError::PriceBandExceeded { band_pct: p * 100.0 });
        }
    }

    Ok(ShapedOrderPrice {
        limit_px: Px(limit_px),
        shaped_ref_px: Px(moved_ref),
        stop_px,
        sz: req.sz,
    })
}
