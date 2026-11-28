//! Node #115 `eth_feeHistory` rules (`evm_rpc/src/evm_rpc.rs`, `reth_rpc_helpers_copied.rs`).
//!
//! Grounded in `research/work-items/RE-011-evm-fee-history-115` (`0x2a1fd20`):
//! - Five-block cap (`MAX_FEE_HISTORY_BLOCKS = 5`).
//! - Up to 100 reward percentiles (`MAX_REWARD_PERCENTILES = 100`).
//! - Adjacent-pair check (`prev <= 100.0 && prev <= next`).
//! - Weighted reward selection with `percentile * total / 100.0` threshold and
//!   overflow-checked cumulative weight.
//! - Blob gas divisor `786432.0`.

use node115_block_number_text::NumberSelector;

pub const MAX_FEE_HISTORY_BLOCKS: u64 = 5;
pub const MAX_REWARD_PERCENTILES: usize = 100;
pub const BLOB_GAS_DIVISOR: f64 = 786_432.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeHistoryError {
    /// Internal tag `0x17`: more than 100 percentiles or non-monotonic / > 100.0.
    InvalidRewardPercentiles,
    /// Internal tag `9`: height `u64::MAX` overflow or inverted range.
    InvalidBlockRange,
    /// Weight sum overflowed `u64`.
    WeightOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeHistoryRange {
    pub oldest_block: u64,
    pub newest_block: u64,
    pub count: u64,
}

/// Validate optional reward percentiles matching `0x2a20053..0x2a200b2`.
///
/// Mirrors the binary's adjacent-pair `UCOMISD` check: rejects `len > 100`,
/// rejects any adjacent pair where `prev > 100.0` or `prev > next` (or NaN).
pub fn validate_reward_percentiles(percentiles: &[f64]) -> Result<(), FeeHistoryError> {
    if percentiles.len() > MAX_REWARD_PERCENTILES {
        return Err(FeeHistoryError::InvalidRewardPercentiles);
    }
    for win in percentiles.windows(2) {
        let prev = win[0];
        let next = win[1];
        if !(prev <= 100.0 && prev <= next) {
            return Err(FeeHistoryError::InvalidRewardPercentiles);
        }
    }
    Ok(())
}

/// Compute the inclusive `[oldest_block, newest_block]` range (`0x2a1fe6b..0x2a201aa`).
///
/// Returns `Ok(None)` when `block_count == 0` (empty result short-circuit).
pub fn compute_fee_history_range(
    block_count: u64,
    selector: NumberSelector,
    latest_height: u64,
) -> Result<Option<FeeHistoryRange>, FeeHistoryError> {
    if block_count == 0 {
        return Ok(None);
    }
    let mut capped = block_count.min(MAX_FEE_HISTORY_BLOCKS);
    let height = match selector.raw_mode {
        5 => selector.number.ok_or(FeeHistoryError::InvalidBlockRange)?,
        4 => {
            // A positive pending request still checks the resolved interval after this decrement.
            capped = capped.saturating_sub(1);
            latest_height
        }
        _ => latest_height,
    };
    let end_exclusive = height
        .checked_add(1)
        .ok_or(FeeHistoryError::InvalidBlockRange)?;
    let n = capped.min(end_exclusive);
    let oldest = end_exclusive - n;
    if oldest > height {
        return Err(FeeHistoryError::InvalidBlockRange);
    }
    Ok(Some(FeeHistoryRange {
        oldest_block: oldest,
        newest_block: height,
        count: n,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewardRow {
    pub effective_priority_fee: u128,
    pub gas_used: u64,
}

/// Select weighted rewards for sorted `rows` matching `0x2a20078..0x2a200b4` (`RE-011-evm-fee-history-115`).
pub fn select_weighted_rewards(
    sorted_rows: &[RewardRow],
    total_gas_used: u64,
    percentiles: &[f64],
) -> Result<Vec<u128>, FeeHistoryError> {
    if sorted_rows.is_empty() {
        return Ok(vec![0u128; percentiles.len()]);
    }
    let mut out = Vec::with_capacity(percentiles.len());
    let mut cursor = 0usize;
    let mut acc_weight = sorted_rows[0].gas_used;
    let total_f64 = total_gas_used as f64;

    for &p in percentiles {
        let thresh_f64 = (p * total_f64) / 100.0;
        let threshold = if thresh_f64 <= 0.0 || thresh_f64.is_nan() {
            0u64
        } else if thresh_f64 >= u64::MAX as f64 {
            u64::MAX
        } else {
            thresh_f64 as u64
        };
        while acc_weight < threshold && cursor + 1 < sorted_rows.len() {
            cursor += 1;
            acc_weight = acc_weight
                .checked_add(sorted_rows[cursor].gas_used)
                .ok_or(FeeHistoryError::WeightOverflow)?;
        }
        out.push(sorted_rows[cursor].effective_priority_fee);
    }
    Ok(out)
}
