//! Node #115 0x422e0f0 with selected-key fold 0x4351520.
//! A checked weighted threshold, not structural equality of two iterators.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;
pub type Key = [u8; 32];

/// Values are materialized native 40-byte row+32 words. Physical tree traversal,
/// materialization and authentication are separate prerequisites. This accepts
/// key yields without silently imposing deduplication on the helper contract.
pub fn exceeds_threshold(
    weights: &BTreeMap<Key, u64>,
    selected: impl IntoIterator<Item = Key>,
) -> bool {
    let mut selected_sum = Some(0u64);
    for key in selected {
        if let Some(weight) = weights.get(&key) {
            selected_sum = selected_sum.and_then(|sum| sum.checked_add(*weight));
            if selected_sum.is_none() {
                break;
            }
        }
    }
    // The native predicate still computes its independent total after a failed
    // selected fold. There are no native diagnostic callbacks in these folds.
    let mut total = Some(0u64);
    for weight in weights.values() {
        total = total.and_then(|sum| sum.checked_add(*weight));
        if total.is_none() {
            break;
        }
    }
    match (selected_sum, total) {
        (Some(selected), Some(total)) => u128::from(selected) * 3 > u128::from(total) * 2,
        _ => false,
    }
}

/// Decode the observed key/value fields, without assigning economic identities.
pub fn row_fields(row: &[u8; 40]) -> (Key, u64) {
    let mut key = [0; 32];
    key.copy_from_slice(&row[..32]);
    let mut word = [0; 8];
    word.copy_from_slice(&row[32..]);
    (key, u64::from_le_bytes(word))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(n: u8) -> Key {
        let mut k = [0; 32];
        k[31] = n;
        k
    }
    #[test]
    fn strict_weight_not_row_count_or_equality() {
        let map = BTreeMap::from([(key(1), 2), (key(2), 1)]);
        assert!(!exceeds_threshold(&map, [key(1)]));
        assert!(exceeds_threshold(&map, [key(1), key(2)]));
        let skew = BTreeMap::from([(key(1), 99), (key(2), 1), (key(3), 1)]);
        assert!(exceeds_threshold(&skew, [key(1)]));
        assert!(!exceeds_threshold(&skew, [key(2), key(3)]));
    }
    #[test]
    fn missing_keys_and_zero_population() {
        assert!(!exceeds_threshold(&BTreeMap::new(), [key(1)]));
        let map = BTreeMap::from([(key(1), 3)]);
        assert!(!exceeds_threshold(&map, [key(2)]));
        assert!(exceeds_threshold(&map, [key(2), key(1)]));
    }
    #[test]
    fn overflow_refuses_instead_of_saturating_or_wrapping() {
        let map = BTreeMap::from([(key(1), u64::MAX), (key(2), 1)]);
        assert!(!exceeds_threshold(&map, [key(1)])); // total overflows
        let one = BTreeMap::from([(key(1), u64::MAX)]);
        assert!(exceeds_threshold(&one, [key(1)])); // 128-bit cross products
        assert!(!exceeds_threshold(&one, [key(1), key(1)])); // repeated yields overflow
    }
    #[test]
    fn all_three_key_small_weights_match_integer_inequality() {
        for a in 0..=8 {
            for b in 0..=8 {
                for c in 0..=8 {
                    let map = BTreeMap::from([(key(1), a), (key(2), b), (key(3), c)]);
                    for mask in 0..8 {
                        let selected = (0..3).filter(|i| mask & (1 << i) != 0).map(|i| key(i + 1));
                        let picked = [a, b, c]
                            .into_iter()
                            .enumerate()
                            .filter(|(i, _)| mask & (1 << i) != 0)
                            .map(|(_, w)| w)
                            .sum::<u64>();
                        // Independent integer boundary: strictly more than floor(2*total/3).
                        assert_eq!(
                            exceeds_threshold(&map, selected),
                            picked > 2 * (a + b + c) / 3
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn fields_use_all_key_bytes_and_little_endian_word() {
        let mut row = [0; 40];
        for (i, b) in row[..32].iter_mut().enumerate() {
            *b = i as u8;
        }
        row[32..].copy_from_slice(&0xfedcba9876543210u64.to_le_bytes());
        let (k, w) = row_fields(&row);
        assert_eq!(k, core::array::from_fn(|i| i as u8));
        assert_eq!(w, 0xfedcba9876543210);
        let map = BTreeMap::from([(k, w)]);
        let mut different = k;
        different[0] ^= 1;
        assert!(!exceeds_threshold(&map, [different]));
    }
}
