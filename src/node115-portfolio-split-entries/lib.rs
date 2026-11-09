//! Owned unique-key composition of 0x3f10c10 with its previously opaque entry
//! helpers. Allocation, diagnostics and native physical containers are excluded.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::BTreeMap;

/// The occupied branch of 0x3cde300 replaces, rather than accumulating.
pub fn replace_negative(map: &mut BTreeMap<u64, u64>, key: u64, magnitude: u64) -> Option<u64> {
    map.insert(key, magnitude)
}

/// 0x3cd0da0 / 0x3f14f20 preserves occupied values and initializes vacancies to 0.
/// The caller's checked multiplication occurs before obtaining this entry.
pub fn add_positive(map: &mut BTreeMap<u64, u64>, key: u64, quantity: u64) {
    if let Some(scaled) = quantity.checked_mul(100) {
        let cell = map.entry(key).or_insert(0);
        *cell = cell.saturating_add(scaled);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Split {
    pub negative: BTreeMap<u64, u64>,
    pub positive: BTreeMap<u64, u64>,
}

/// Input is a valid unique-key native-map observation, not an arbitrary duplicate
/// wire sequence. The seed is moved into the positive result, preserving keys
/// that do not occur in the consumed input. A key may exist in both outputs.
pub fn split(input: BTreeMap<u64, i64>, mut positive: BTreeMap<u64, u64>) -> Split {
    let mut negative = BTreeMap::new();
    for (key, quantity) in input {
        if quantity < 0 {
            replace_negative(&mut negative, key, quantity.saturating_abs() as u64);
        } else if quantity != 0 {
            add_positive(&mut positive, key, quantity as u64);
        }
    }
    Split { negative, positive }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn occupied_policies_differ() {
        let mut negative = BTreeMap::from([(4, 9)]);
        assert_eq!(replace_negative(&mut negative, 4, 7), Some(9));
        assert_eq!(negative[&4], 7);
        assert_eq!(replace_negative(&mut negative, 5, 8), None);
        let mut positive = BTreeMap::from([(4, 9)]);
        add_positive(&mut positive, 4, 7);
        add_positive(&mut positive, 4, 1);
        assert_eq!(positive[&4], 809);
        add_positive(&mut positive, 5, 8);
        assert_eq!(positive[&5], 800);
    }
    #[test]
    fn overflow_skip_precedes_entry_creation_or_mutation() {
        let mut seed = BTreeMap::from([(9, 123)]);
        add_positive(&mut seed, 9, u64::MAX / 100 + 1);
        add_positive(&mut seed, 10, u64::MAX / 100 + 1);
        assert_eq!(seed, BTreeMap::from([(9, 123)]));
        add_positive(&mut seed, 10, u64::MAX / 100);
        assert_eq!(seed[&10], u64::MAX / 100 * 100);
    }
    #[test]
    fn source_owned_composition_retains_seed_and_separates_signs() {
        let input = BTreeMap::from([(1, -7), (2, 3), (3, 0), (4, i64::MIN), (5, i64::MAX)]);
        let seed = BTreeMap::from([(1, 19), (2, 11), (3, 22), (7, 33)]);
        let got = split(input, seed);
        assert_eq!(got.negative, BTreeMap::from([(1, 7), (4, i64::MAX as u64)]));
        assert_eq!(
            got.positive,
            BTreeMap::from([(1, 19), (2, 311), (3, 22), (7, 33)])
        );
    }
    #[test]
    fn wide_arithmetic_oracle_for_seed_addition() {
        let values = [
            0,
            1,
            2,
            99,
            100,
            u64::MAX / 100,
            u64::MAX / 100 + 1,
            i64::MAX as u64,
            u64::MAX,
        ];
        let seeds = [0, 1, 99, u64::MAX - 100, u64::MAX - 1, u64::MAX];
        for value in values {
            for old in seeds {
                let mut map = BTreeMap::from([(u64::MAX, old)]);
                add_positive(&mut map, u64::MAX, value);
                let product = u128::from(value) * 100;
                let expected = if product > u128::from(u64::MAX) {
                    old
                } else {
                    (u128::from(old) + product).min(u128::from(u64::MAX)) as u64
                };
                assert_eq!(map[&u64::MAX], expected);
            }
        }
    }
    #[test]
    fn empty_negative_output_and_empty_seed() {
        assert_eq!(
            split(BTreeMap::new(), BTreeMap::new()),
            Split {
                negative: BTreeMap::new(),
                positive: BTreeMap::new()
            }
        );
    }
}
