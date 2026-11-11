//! Selected fee-history reward row and ordered-percentile arithmetic.
//!
//! Rows supplied to selection must already be in the caller's established
//! order. The total is independent of their weights. This models no sorting,
//! receipt clone, RPC schema, allocator failure, native panic or runtime ABI.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec::Vec;

/// Raw fields at offsets 0, 0x40, 0x50 and 0x60 of one transaction row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxFields {
    pub prefix: u128,
    pub zero_cap: u128,
    pub other_cap: u128,
    pub priority_cap: u128,
}

/// Logical active fields of one native 32-byte reward row; padding omitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardRow {
    pub reward: u128,
    pub gas: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CumulativeUnderflow {
    pub index: usize,
}

/// Construct the zipped prefix, with the observed caller's zero initial gas.
/// Native underflow reaches a panic path; this owned API returns its index.
pub fn build_reward_rows(
    tx: &[TxFields],
    cumulative: &[u64],
    base_fee: u64,
) -> Result<Vec<RewardRow>, CumulativeUnderflow> {
    let mut rows = Vec::with_capacity(core::cmp::min(tx.len(), cumulative.len()));
    let mut previous = 0u64;
    for (index, (item, &current)) in tx.iter().zip(cumulative).enumerate() {
        let cap = if item.prefix == 0 {
            item.zero_cap
        } else {
            item.other_cap
        };
        let difference = cap.saturating_sub(u128::from(base_fee));
        let reward = if item.prefix < 2 {
            difference
        } else {
            difference.min(item.priority_cap)
        };
        let gas = current
            .checked_sub(previous)
            .ok_or(CumulativeUnderflow { index })?;
        rows.push(RewardRow { reward, gas });
        previous = current;
    }
    Ok(rows)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightOverflow {
    pub index: usize,
}

/// Select from rows already ordered by the caller, keeping a forward-only cursor.
/// The native cumulative overflow is a failure path; this owned API returns it.
/// Floating operations assume binary64 round-to-nearest/ties-to-even.
pub fn select_ordered(
    rows: &[RewardRow],
    percentiles: &[f64],
    total: u64,
) -> Result<Vec<u128>, WeightOverflow> {
    let mut out = Vec::with_capacity(percentiles.len());
    let Some(first) = rows.first() else {
        out.resize(percentiles.len(), 0);
        return Ok(out);
    };
    let mut cursor = 0usize;
    let mut accumulated = first.gas;
    for &percentile in percentiles {
        let threshold = ((percentile * total as f64) / 100.0) as u64;
        while accumulated < threshold && cursor < rows.len() - 1 {
            cursor += 1;
            accumulated = accumulated
                .checked_add(rows[cursor].gas)
                .ok_or(WeightOverflow { index: cursor })?;
        }
        out.push(rows[cursor].reward);
    }
    Ok(out)
}
