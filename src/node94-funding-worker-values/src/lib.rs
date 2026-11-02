//! Conditional supplied-state values for node94 worker `0x3757610`.
//!
//! Native correspondence premises and pre-source expectations are in
//! `research/work-items/RE-007-funding-worker-values-94`. This library records
//! saturation requests; it does not deliver native diagnostics or reproduce
//! native failure state, allocations, pointer layouts or scheduler behavior.

use std::collections::{BTreeMap, BTreeSet};

const SIGN: u64 = 1 << 63;
const INFINITY: u64 = 0x7ff0_0000_0000_0000;
const FRACTION: u64 = (1 << 52) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub tag: u32,
    pub local_balance: i64,
    pub size: i64,
    pub accumulators: [i64; 3],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserState {
    pub balance: i64,
    pub positions: BTreeMap<u64, Position>,
}

pub struct Inputs<'a> {
    pub address: [u8; 20],
    pub bypass: u8,
    pub members: &'a BTreeSet<[u8; 20]>,
    pub time: [u8; 12],
    pub metadata: &'a [i64],
    pub rates: &'a BTreeMap<u64, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub asset: u64,
    pub payment: i64,
    pub original_size: i64,
    pub raw_rate: u64,
    pub product: i64,
    pub address: [u8; 20],
    pub time: [u8; 12],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Maximum {
    pub asset: u64,
    pub magnitude: u64,
    pub address: [u8; 20],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub sum: i64,
    pub maximum: Option<Maximum>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestField {
    SelectedBalance = 0,
    Accumulator0 = 1,
    Accumulator1 = 2,
    Accumulator2 = 3,
    Summary = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub asset: u64,
    pub field: RequestField,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The immutable input state is unchanged; no native payload is inferred.
    Excluded,
    Accepted {
        state: UserState,
        rows: Vec<Row>,
        summary: Summary,
        requests: Vec<Request>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RefusalKind {
    MetadataIndex = 0,
    NegativeMetadata = 1,
    ProductOverflow = 2,
    MinimumAmount = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub asset: u64,
    pub kind: RefusalKind,
}

fn magnitude(value: i64) -> u64 {
    if value < 0 {
        (value as u64).wrapping_neg()
    } else {
        value as u64
    }
}

// Exact rounding of one nonnegative dyadic magnitude * 2^power. The only
// callers supply at most 106 significand bits; no arbitrary instruction state.
fn rounded_bits(magnitude: u128, power: i32, negative: bool) -> u64 {
    let sign = if negative { SIGN } else { 0 };
    if magnitude == 0 {
        return sign;
    }
    let top = 127 - magnitude.leading_zeros() as i32 + power;
    let quantum = (top - 52).max(-1074);
    let shift = quantum - power;
    let rounded = if shift > 128 {
        0
    } else if shift == 128 {
        u128::from(magnitude > (1_u128 << 127))
    } else if shift > 0 {
        let quotient = magnitude >> shift;
        let remainder = magnitude & ((1_u128 << shift) - 1);
        let halfway = 1_u128 << (shift - 1);
        quotient + u128::from(remainder > halfway || (remainder == halfway && quotient & 1 != 0))
    } else {
        // This left shift is at most 52 by the selected quantum's definition.
        magnitude << -shift
    };
    if rounded == 0 {
        return sign;
    }
    let bits = 128 - rounded.leading_zeros();
    let exponent = bits as i32 - 1 + quantum;
    if exponent > 1023 {
        return sign | INFINITY;
    }
    if exponent < -1022 {
        // A nonzero subnormal uses the fixed quantum 2^-1074.
        return sign | rounded as u64;
    }
    let normalized = if bits > 53 {
        rounded >> (bits - 53)
    } else {
        rounded << (53 - bits)
    };
    sign | (((exponent + 1023) as u64) << 52) | (normalized as u64 & FRACTION)
}

fn finite_parts(bits: u64) -> (u128, i32) {
    let exponent = ((bits >> 52) & 2047) as i32;
    if exponent == 0 {
        ((bits & FRACTION) as u128, -1074)
    } else {
        (((bits & FRACTION) | (1 << 52)) as u128, exponent - 1075)
    }
}

fn funding_amount(product: i64, rate: u64) -> Option<i64> {
    if rate & !SIGN >= INFINITY {
        return Some(0);
    }
    let integer_bits = rounded_bits(magnitude(product) as u128, 0, product < 0);
    let (integer_significand, integer_power) = finite_parts(integer_bits);
    let (rate_significand, rate_power) = finite_parts(rate);
    let bits = rounded_bits(
        integer_significand * rate_significand,
        integer_power + rate_power,
        (integer_bits ^ rate) & SIGN != 0,
    );
    let absolute = bits & !SIGN;
    if absolute >= INFINITY {
        return Some(0);
    }
    if absolute >= 0x43e0_0000_0000_0000 {
        return if bits & SIGN != 0 {
            None
        } else {
            Some(i64::MAX)
        };
    }
    let (significand, power) = finite_parts(bits);
    let truncated = if power >= 0 {
        significand << power
    } else if power <= -128 {
        0
    } else {
        significand >> -power
    } as i64;
    Some(if bits & SIGN != 0 {
        -truncated
    } else {
        truncated
    })
}

fn subtract(old: i64, amount: i64, asset: u64, requests: &mut Vec<Request>) -> i64 {
    if old.checked_sub(amount).is_none() {
        requests.push(Request {
            asset,
            field: RequestField::SelectedBalance,
        });
    }
    old.saturating_sub(amount)
}

/// Compute only the admitted successful-domain values on immutable inputs.
///
/// A refusal is a safe supplied-state result, not native panic/failure-state
/// equivalence. Native failure may follow prior effects. Collection allocation
/// must succeed; no allocation recovery or rollback contract is provided.
pub fn funding_worker(inputs: &Inputs<'_>, original: &UserState) -> Result<Outcome, Refusal> {
    if inputs.bypass == 0 && !inputs.members.contains(&inputs.address) {
        return Ok(Outcome::Excluded);
    }
    let mut state = original.clone();
    let mut rows = Vec::new();
    let mut requests = Vec::new();
    for (&asset, position) in &mut state.positions {
        let Some(&raw_rate) = inputs.rates.get(&asset) else {
            continue;
        };
        if raw_rate & !SIGN == 0 {
            continue;
        }
        let index = (asset % 10000) as usize;
        if index >= inputs.metadata.len() {
            return Err(Refusal {
                asset,
                kind: RefusalKind::MetadataIndex,
            });
        }
        if position.size == 0 {
            continue;
        }
        let price = inputs.metadata[index];
        if price < 0 {
            return Err(Refusal {
                asset,
                kind: RefusalKind::NegativeMetadata,
            });
        }
        let product = price.checked_mul(position.size).ok_or(Refusal {
            asset,
            kind: RefusalKind::ProductOverflow,
        })?;
        let amount = funding_amount(product, raw_rate).ok_or(Refusal {
            asset,
            kind: RefusalKind::MinimumAmount,
        })?;
        if inputs.time[..4].iter().all(|&byte| byte == 0) {
            continue;
        }
        if position.tag == 1 {
            position.local_balance = subtract(position.local_balance, amount, asset, &mut requests);
        } else {
            state.balance = subtract(state.balance, amount, asset, &mut requests);
        }
        for (value, field) in position.accumulators.iter_mut().zip([
            RequestField::Accumulator0,
            RequestField::Accumulator1,
            RequestField::Accumulator2,
        ]) {
            if value.checked_add(amount).is_none() {
                requests.push(Request { asset, field });
            }
            *value = value.saturating_add(amount);
        }
        rows.push(Row {
            asset,
            payment: -amount,
            original_size: position.size,
            raw_rate,
            product,
            address: inputs.address,
            time: inputs.time,
        });
    }
    let mut summary = Summary {
        sum: 0,
        maximum: None,
    };
    for row in &rows {
        if summary.sum.checked_add(row.payment).is_none() {
            requests.push(Request {
                asset: row.asset,
                field: RequestField::Summary,
            });
        }
        summary.sum = summary.sum.saturating_add(row.payment);
        let candidate = magnitude(row.product);
        if summary
            .maximum
            .as_ref()
            .is_none_or(|saved| candidate > saved.magnitude)
        {
            summary.maximum = Some(Maximum {
                asset: row.asset,
                magnitude: candidate,
                address: row.address,
            });
        }
    }
    Ok(Outcome::Accepted {
        state,
        rows,
        summary,
        requests,
    })
}
