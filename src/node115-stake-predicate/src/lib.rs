//! Conditional value reconstruction of node #115's flat-map stake predicate.
//!
//! This safe value API has no native layout, tree, ABI or runtime claim. See
//! `research/work-items/RE-008-node115-saturating-stake-predicate` for the
//! digest-bound native contract and its ordinary-import/storage assumptions.
#![no_std]
#![forbid(unsafe_code)]

use core::cmp::Ordering;

/// One physical map row. This is not a native `repr(C)` layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    pub key: [u8; 20],
    pub weight: u64,
}

/// Safe observations: both intermediate fold values and the predicate bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub selected_sum: u64,
    pub total_sum: u64,
    pub passes: bool,
}

/// Chosen host admission errors, not recovered native error variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidView {
    Bounds,
    Order,
}

/// Computes the complete supplied selected-key/all-live-weight operation.
///
/// Live keys, starting at `head` and wrapping through `rows`, must be sorted
/// nondecreasingly by all twenty unsigned bytes. Inactive rows are ignored.
/// Bounds are checked before ordering; empty storage requires head zero, and
/// a nonempty allocation requires `head < rows.len()` even when `live == 0`.
///
/// Selected keys may occur in any order and may repeat. A missing key adds
/// nothing. On a wrapped view, equality with physical row zero selects that
/// seam row immediately; otherwise the last equal key of the relevant segment
/// supplies its weight. Both folds saturate to `u64::MAX` before the strict
/// wider comparison `2 * total_sum < 3 * selected_sum`.
///
/// Native correspondence additionally requires the complete `selected` sequence
/// to equal the native key tree's in-order expansion. This function does not
/// validate a native tree or establish original constructor validity.
pub fn predicate(
    rows: &[Row],
    head: usize,
    live: usize,
    selected: &[[u8; 20]],
) -> Result<Observation, InvalidView> {
    let capacity = rows.len();
    if live > capacity || (capacity == 0 && head != 0) || (capacity != 0 && head >= capacity) {
        return Err(InvalidView::Bounds);
    }

    // Each addition stays within the physical slice; head + logical may not.
    let tail = capacity - head;
    let physical = |logical: usize| {
        if logical < tail {
            head + logical
        } else {
            logical - tail
        }
    };
    for logical in 1..live {
        if rows[physical(logical - 1)].key > rows[physical(logical)].key {
            return Err(InvalidView::Order);
        }
    }

    let first_len = live.min(tail);
    let first = &rows[head..head + first_len];
    let second = &rows[..live - first_len];
    let mut selected_sum = 0u64;
    for key in selected {
        if let Some(row) = lookup(first, second, key) {
            selected_sum = selected_sum.saturating_add(row.weight);
        }
    }

    // Keep complete traversal even after saturation. Value-only comparisons do
    // not establish native read/call effects or distinguish every early stop.
    let mut total_sum = 0u64;
    for row in first.iter().chain(second.iter()) {
        total_sum = total_sum.saturating_add(row.weight);
    }
    let passes = 2u128 * u128::from(total_sum) < 3u128 * u128::from(selected_sum);
    Ok(Observation {
        selected_sum,
        total_sum,
        passes,
    })
}

fn lookup<'a>(first: &'a [Row], second: &'a [Row], key: &[u8; 20]) -> Option<&'a Row> {
    if let Some(seam) = second.first() {
        match key.cmp(&seam.key) {
            Ordering::Equal => Some(seam),
            Ordering::Less => last_equal(first, key),
            Ordering::Greater => last_equal(second, key),
        }
    } else {
        last_equal(first, key)
    }
}

fn last_equal<'a>(rows: &'a [Row], key: &[u8; 20]) -> Option<&'a Row> {
    // Upper bound over a contiguous segment. This independently expressed
    // binary search differs from the reference's linear order-statistic count.
    let mut low = 0;
    let mut high = rows.len();
    while low < high {
        let middle = low + (high - low) / 2;
        if rows[middle].key <= *key {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    let row = rows.get(low.checked_sub(1)?)?;
    (row.key == *key).then_some(row)
}
