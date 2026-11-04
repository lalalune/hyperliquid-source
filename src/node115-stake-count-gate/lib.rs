//! Logical return-value reconstruction of Node115's two-collection gate.
//! Target: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
//! Native ABI, physical map traversal and allocation/unwind behavior are not
//! implemented by this safe, immutable-value interface.

use std::collections::{BTreeMap, BTreeSet};

pub type Key = [u8; 20];

/// Evaluate the complete normal Boolean path at linked VA
/// 0x28aa050..0x28aa36e, using the keys projected from its two input maps.
///
/// The first and second slices represent different native fields. Values in
/// those source maps are not read by the key collector. The weight map and
/// member set must be immutable for the entire call. These are logical values,
/// not declarations of the original Rust types or memory layout.
pub fn evaluate(
    first_keys: &[Key],
    second_keys: &[Key],
    weights: &BTreeMap<Key, u64>,
    fraction: f64,
    members: &BTreeSet<Key>,
) -> bool {
    let first: BTreeSet<Key> = first_keys.iter().copied().collect();
    let selected = first
        .iter()
        .filter_map(|key| weights.get(key))
        .fold(0_u64, |sum, value| sum.saturating_add(*value));
    let total = weights
        .values()
        .fold(0_u64, |sum, value| sum.saturating_add(*value));
    let weight_passes = 2 * u128::from(total) < 3 * u128::from(selected);
    // The native caller destroys this first temporary before its branch and
    // before collecting the second map.
    drop(first);
    if !weight_passes {
        return false;
    }

    let second: BTreeSet<Key> = second_keys.iter().copied().collect();
    let result = count_gate(&second, fraction, members);
    drop(second);
    result
}

fn count_gate(selected: &BTreeSet<Key>, fraction: f64, members: &BTreeSet<Key>) -> bool {
    // The native zero arm includes both signs of zero and precedes iteration.
    if fraction == 0.0 {
        return true;
    }
    let mut matches = 0_u64;
    for key in selected {
        if members.contains(key) {
            matches = matches.checked_add(1).expect("matching-key count overflow");
        }
    }
    (matches as f64) > fraction * (members.len() as f64)
}
