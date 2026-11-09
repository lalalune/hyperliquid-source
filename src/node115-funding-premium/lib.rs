//! Typed book impact walk and selected funding-premium composition for node115.
//!
//! Levels are supplied in native visitation order. Collection ABI, concurrent
//! access, diagnostics and live book storage are outside this logical model.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::collections::{BTreeMap, BTreeSet};

const NOTIONAL_LIMIT: u128 = (1u128 << 63) - 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    /// The native tag-2 slot terminates the current level's order chain.
    Vacant,
    Order {
        quantity: u64,
        next: Option<usize>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Level {
    pub signed_price: i64,
    /// `None` represents a non-present native head; an invalid index also fails.
    pub head: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub struct Book<'a> {
    /// Already in the selected native iterator's order; no sorting is added.
    pub levels: &'a [Level],
    pub orders: &'a [Slot],
}

/// Owned fault categories; these are not native panic/error objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Market,
    Decimals,
    /// A zero-price level reaches the partial-fill division.
    ZeroPriceDivision,
    /// An input outside the terminating-chain precondition.
    CyclicChain,
}

/// Logical projection of the selected metadata row.
#[derive(Clone, Copy, Debug)]
pub struct Market<'a> {
    pub dex: u64,
    pub decimals: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    pub default_notional: u64,
    pub notional_overrides: &'a BTreeMap<u64, u64>,
    pub divide_by_hundred: &'a BTreeSet<u64>,
    pub impact_mode: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Premium {
    pub value: f64,
    pub first_impact: u64,
    pub second_impact: u64,
}

fn product(price: u64, quantity: u64) -> Option<u64> {
    let n = u128::from(price) * u128::from(quantity);
    (n <= NOTIONAL_LIMIT).then_some(n as u64)
}

/// The selected impact walk's u64 result; zero is its observed failure sentinel.
///
/// Saturating additions model continuation after the native diagnostic helper
/// returns. This function emits no diagnostics. Acyclic links are the native
/// terminating-input precondition; the owned wrapper detects a violation.
pub fn impact(book: Book<'_>, target: u64) -> Result<u64, Fault> {
    let mut notional = 0u64;
    let mut quantity = 0u64;
    for level in book.levels {
        let Some(mut index) = level.head else {
            return Ok(0);
        };
        if index >= book.orders.len() {
            return Ok(0);
        }
        let mut level_quantity = 0u64;
        let mut steps = 0usize;
        loop {
            if steps == book.orders.len() {
                return Err(Fault::CyclicChain);
            }
            steps += 1;
            match book.orders[index] {
                Slot::Vacant => break,
                Slot::Order { quantity: q, next } => {
                    level_quantity = level_quantity.saturating_add(q);
                    match next {
                        Some(next_index) if next_index < book.orders.len() => index = next_index,
                        _ => break,
                    }
                }
            }
        }
        if level_quantity == 0 {
            return Ok(0);
        }
        let price = level.signed_price.unsigned_abs();
        let Some(full) = product(price, level_quantity) else {
            return Ok(0);
        };
        let next_notional = notional.saturating_add(full);
        if next_notional >= target {
            if price == 0 {
                return Err(Fault::ZeroPriceDivision);
            }
            let partial_quantity = target.saturating_sub(notional) / price;
            let Some(partial) = product(price, partial_quantity) else {
                return Ok(0);
            };
            let total_notional = notional.saturating_add(partial);
            let total_quantity = quantity.saturating_add(partial_quantity);
            // Native compares wrapping(quantity-1) >= notional before dividing.
            if total_quantity.wrapping_sub(1) >= total_notional {
                return Ok(0);
            }
            return Ok(total_notional / total_quantity);
        }
        notional = next_notional;
        quantity = quantity.saturating_add(level_quantity);
    }
    Ok(0)
}

/// Compute the selected premium from logical metadata, config and both books.
/// `None` corresponds to the caller's zero-oracle/zero-impact absence path.
pub fn premium(
    asset: u64,
    oracle: u64,
    market: Market<'_>,
    config: Config<'_>,
    first: Book<'_>,
    second: Book<'_>,
) -> Result<Option<Premium>, Fault> {
    let local = (asset % 10_000) as usize;
    if asset / 10_000 != market.dex || local >= market.decimals.len() {
        return Err(Fault::Market);
    }
    let decimals = market.decimals[local];
    if decimals >= 7 {
        return Err(Fault::Decimals);
    }
    let scale = 10u64.pow(6 - u32::from(decimals)) as f64;
    let reference = oracle as f64 / scale;
    if reference == 0.0 {
        return Ok(None);
    }
    let target = config
        .notional_overrides
        .get(&asset)
        .copied()
        .unwrap_or(config.default_notional);
    let first_impact = impact(first, target)?;
    // The native caller invokes both helpers before testing either zero result.
    let second_impact = impact(second, target)?;
    if first_impact == 0 || second_impact == 0 {
        return Ok(None);
    }
    let first_scaled = first_impact as f64 / scale;
    let second_scaled = second_impact as f64 / scale;
    let mut value = if config.impact_mode {
        let a = first_scaled - reference;
        let b = -(second_scaled - reference);
        let above = if a > 0.0 { a } else { 0.0 };
        let below = if b > 0.0 { b } else { 0.0 };
        (above - below) / reference
    } else {
        // Both scaled u64 values are <= u64::MAX, far below half f64::MAX:
        // only the native add-then-multiply midpoint branch is reachable here.
        ((first_scaled + second_scaled) * 0.5) / reference - 1.0
    };
    if config.divide_by_hundred.contains(&asset) {
        value /= 100.0;
    }
    if value.is_finite() {
        value = value.clamp(-0.5, 0.5);
    }
    Ok(Some(Premium {
        value,
        first_impact,
        second_impact,
    }))
}
