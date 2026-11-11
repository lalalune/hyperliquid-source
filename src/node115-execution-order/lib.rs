//! Logical comparisons behind selected execution-row ordering.
//! Native iterator/storage representation remains a premise.
use std::cmp::Ordering;

pub type Key = [u8; 20];

/// Logical ordered key sequence read by 0x23316c0 / 0x243b7a0.
/// Each input must be in the visitation order supplied by its native iterator.
pub fn compare_keys(left: &[Key], right: &[Key]) -> Ordering {
    left.cmp(right)
}

/// Logical 20-byte key and unsigned value read from a 32-byte map row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub key: Key,
    pub value: u64,
}

/// Decode selected row fields; bytes 20..24 are padding and ignored.
pub fn decode_entry(row: &[u8; 32]) -> Entry {
    Entry {
        key: row[..20].try_into().unwrap(),
        value: u64::from_le_bytes(row[24..32].try_into().unwrap()),
    }
}

/// Logical fields observed by 0x26a7880. Map and set inputs must be in native
/// iteration order; pointer descriptors and physical traversal are not modeled.
#[derive(Clone, Copy, Debug)]
pub struct Row64<'a> {
    pub word: u64,
    pub map: &'a [Entry],
    pub keys: &'a [Key],
}

pub fn compare_64(left: Row64<'_>, right: Row64<'_>) -> Ordering {
    left.word
        .cmp(&right.word)
        .then_with(|| left.map.cmp(right.map))
        .then_with(|| compare_keys(left.keys, right.keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_order_and_prefix() {
        let a = [1; 20];
        let mut b = a;
        b[19] = 2;
        assert_eq!(compare_keys(&[a], &[b]), Ordering::Less);
        assert_eq!(compare_keys(&[a], &[a, b]), Ordering::Less);
        assert_eq!(compare_keys(&[a, b], &[a]), Ordering::Greater);
        assert_eq!(compare_keys(&[], &[]), Ordering::Equal);
        for i in 0..20 {
            let mut changed = a;
            changed[i] += 1;
            assert_eq!(compare_keys(&[a], &[changed]), Ordering::Less);
        }
    }
    #[test]
    fn row_fields_and_padding() {
        let mut row = [0u8; 32];
        row[..20].fill(7);
        row[24..].copy_from_slice(&u64::MAX.to_le_bytes());
        let original = decode_entry(&row);
        assert_eq!(original.value, u64::MAX);
        for i in 20..24 {
            row[i] ^= 1;
            assert_eq!(decode_entry(&row), original);
        }
        for i in 0..20 {
            let mut changed = row;
            changed[i] ^= 1;
            assert_ne!(decode_entry(&changed), original);
        }
    }
    #[test]
    fn numeric_then_map_then_set() {
        let low = Entry {
            key: [1; 20],
            value: 0,
        };
        let high = Entry {
            key: [1; 20],
            value: u64::MAX,
        };
        let first = Row64 {
            word: 3,
            map: &[high],
            keys: &[[9; 20]],
        };
        let larger_word = Row64 {
            word: 4,
            map: &[],
            keys: &[],
        };
        assert_eq!(compare_64(first, larger_word), Ordering::Less);
        let second = Row64 {
            word: 3,
            map: &[low],
            keys: &[[9; 20]],
        };
        assert_eq!(compare_64(first, second), Ordering::Greater);
        let third = Row64 {
            word: 3,
            map: &[high],
            keys: &[[10; 20]],
        };
        assert_eq!(compare_64(first, third), Ordering::Less);
        assert_eq!(compare_64(first, first), Ordering::Equal);
    }
    #[test]
    fn tied_selector_contract_witness() {
        // Same signed tie convention as the separately credited #4945 API.
        let rows: [(u64, &[Key]); 4] = [
            (5, &[[1; 20]]),
            (5, &[[1; 20], [0; 20]]),
            (6, &[]),
            (6, &[]),
        ];
        let mut selected = 0;
        for candidate in 1..rows.len() {
            let order = rows[selected]
                .0
                .cmp(&rows[candidate].0)
                .then_with(|| compare_keys(rows[selected].1, rows[candidate].1));
            if order != Ordering::Greater {
                selected = candidate;
            }
        }
        assert_eq!(selected, 3);
    }
    #[test]
    fn independent_pairwise_reference() {
        let keys: Vec<Key> = (0..6)
            .map(|v| {
                let mut k = [0; 20];
                k[0] = v;
                k[19] = 5 - v;
                k
            })
            .collect();
        let entries: Vec<Entry> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| Entry {
                key: *k,
                value: if i % 2 == 0 { u64::MAX } else { i as u64 },
            })
            .collect();
        for left_len in 0..=6 {
            for right_len in 0..=6 {
                for left_start in 0..=6 - left_len {
                    for right_start in 0..=6 - right_len {
                        let l = &entries[left_start..left_start + left_len];
                        let r = &entries[right_start..right_start + right_len];
                        let mut expected = Ordering::Equal;
                        for i in 0..l.len().min(r.len()) {
                            for j in 0..20 {
                                if l[i].key[j] != r[i].key[j] {
                                    expected = l[i].key[j].cmp(&r[i].key[j]);
                                    break;
                                }
                            }
                            if expected != Ordering::Equal {
                                break;
                            }
                            if l[i].value != r[i].value {
                                expected = l[i].value.cmp(&r[i].value);
                                break;
                            }
                        }
                        if expected == Ordering::Equal {
                            expected = l.len().cmp(&r.len());
                        }
                        let left = Row64 {
                            word: 0,
                            map: l,
                            keys: &[],
                        };
                        let right = Row64 {
                            word: 0,
                            map: r,
                            keys: &[],
                        };
                        assert_eq!(compare_64(left, right), expected);
                    }
                }
            }
        }
    }
}
