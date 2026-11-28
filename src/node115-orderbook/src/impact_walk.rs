//! Orderbook impact-price walk (`0x46a6370`) and L2 `nSigFigs`/`mantissa` aggregation
//! grounded in node #115 (`RE-014-book-impact-walk-115`).
//!
//! Binary evidence (`0x46a6370..0x46a685c`, 1,260 B; B-tree step `0x37c5dd0..0x37c5ff4`, 548 B):
//! - Walks one side of the book from best level outward.
//! - Per level: sums resting order sizes with `sat_add` (`qtys/mod.rs:831`); size `0` aborts (`None`).
//! - Computes `level_ntl = px * level_sz`; carry or `> 0x7fff_ffff_ffff_fffe` returns `None`.
//! - Accumulates `running_ntl` (`qtys/impl_ntl.rs:26`) and `running_fill_sz` (`qtys/mod.rs:831`).
//! - At the level reaching `target_ntl`:
//!   `q = (target_ntl - running_ntl) / px`, `p = px * q <= 0x7fff_ffff_ffff_fffe`,
//!   `total = p.sat_add(running_ntl)` (`qtys/mod.rs:833`),
//!   `count = q.sat_add(running_fill_sz)` (`qtys/mod.rs:831`);
//!   if `count == 0 || count - 1 >= total`, returns `None`; else `Some(Px(total / count))`.

use std::collections::BTreeMap;

use node115_assets::pdi::Side;
use node115_assets::qtys::{Ntl, OverflowSink, Px, Sz};

use crate::matching::L2Level;

/// Maximum allowed single-level or partial-level notional product in node #115 `0x46a6370`
/// (`0x7fff_ffff_ffff_fffe`, step 4 & step 5).
pub const MAX_IMPACT_NOTIONAL_PRODUCT: u64 = 0x7fff_ffff_ffff_fffe;

/// Exact Rust reconstruction of node #115 `0x46a6370` (`RE-014-book-impact-walk-115`) over
/// an ordered sequence of `(Px, Sz)` book levels (best-to-worst).
pub fn impact_walk_levels<I>(
    levels: I,
    target_ntl: Ntl,
    sink: &mut impl OverflowSink,
) -> Option<Px>
where
    I: IntoIterator<Item = (Px, Sz)>,
{
    let mut running_ntl = Ntl::ZERO;
    let mut running_fill_sz = Sz::ZERO;

    for (px, level_sz) in levels {
        if px.raw() == 0 || level_sz.is_zero() {
            return None;
        }
        let level_ntl_u128 = u128::from(px.raw()) * u128::from(level_sz.raw());
        if level_ntl_u128 > u128::from(MAX_IMPACT_NOTIONAL_PRODUCT) {
            return None;
        }
        let level_ntl = Ntl(level_ntl_u128 as u64);
        let next_ntl = running_ntl.sat_add(level_ntl, sink);
        if next_ntl.raw() < target_ntl.raw() {
            running_ntl = next_ntl;
            running_fill_sz = running_fill_sz.sat_add(level_sz, sink);
        } else {
            let remaining_ntl = target_ntl.raw().saturating_sub(running_ntl.raw());
            let q = remaining_ntl / px.raw();
            let partial_ntl_u128 = u128::from(px.raw()) * u128::from(q);
            if partial_ntl_u128 > u128::from(MAX_IMPACT_NOTIONAL_PRODUCT) {
                return None;
            }
            let total = Ntl(partial_ntl_u128 as u64).sat_add(running_ntl, sink);
            let count = Sz(q).sat_add(running_fill_sz, sink);
            if count.raw() == 0 || count.raw() > total.raw() {
                return None;
            }
            return Some(Px(total.raw() / count.raw()));
        }
    }
    None
}

/// Rounds a raw positive price to `n_sig_figs` (`2..=5`) and optional `mantissa` (`2` or `5`
/// when `n_sig_figs == 5`), rounding bids DOWN and asks UP so L2 bucketed quotes stay conservative.
/// Matches the public order-book server's unit tick times the mantissa for prices with at most five digits.
pub fn bucket_l2_px(px: Px, side: Side, n_sig_figs: u32, mantissa: Option<u64>) -> Px {
    let raw = px.raw();
    if raw == 0 || !(2..=5).contains(&n_sig_figs) {
        return px;
    }
    let digits = raw.ilog10() + 1;
    let shift = digits.saturating_sub(n_sig_figs);
    let base_step = 10_u64.saturating_pow(shift);
    let step = match (n_sig_figs, mantissa) {
        (5, Some(2)) => base_step.saturating_mul(2),
        (5, Some(5)) => base_step.saturating_mul(5),
        _ => base_step,
    };
    if step <= 1 {
        return px;
    }
    let bucket = match side {
        Side::Bid => (raw / step) * step,
        Side::Ask => raw.div_ceil(step).saturating_mul(step),
    };
    Px(bucket)
}

/// Aggregates L2 book levels into conservative `n_sig_figs`/`mantissa` buckets capped at `max_levels`.
pub fn aggregate_l2_levels(
    levels: &[L2Level],
    side: Side,
    n_sig_figs: Option<u32>,
    mantissa: Option<u64>,
    max_levels: usize,
) -> Vec<L2Level> {
    let Some(sig_figs) = n_sig_figs else {
        return levels.iter().take(max_levels).copied().collect();
    };
    let mut grouped: BTreeMap<i64, L2Level> = BTreeMap::new();
    for lvl in levels {
        let bucket_px = bucket_l2_px(lvl.px, side, sig_figs, mantissa);
        let key = side.signed_price_key(bucket_px.raw());
        let entry = grouped.entry(key).or_insert(L2Level {
            px: bucket_px,
            sz: Sz::ZERO,
            n_orders: 0,
        });
        entry.sz = Sz(entry.sz.raw().saturating_add(lvl.sz.raw()));
        entry.n_orders = entry.n_orders.saturating_add(lvl.n_orders);
    }
    grouped.into_values().take(max_levels).collect()
}
