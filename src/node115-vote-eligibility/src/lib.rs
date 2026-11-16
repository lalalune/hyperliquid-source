//! Logical lookup for the selected 32-byte vote candidate in a current history row.
//! Sorted, unique keys and valid ring geometry are input premises; the native
//! routines do not establish those properties. Missing-row diagnostics are outside
//! this model. Upstream signature verification is a caller-owned boundary.
use std::collections::BTreeMap;

pub type Key = [u8; 32];
pub type Address = [u8; 20];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySet {
    Tree(BTreeMap<Key, Address>),
    /// `rows` is the physical backing, with `len` live keys from `head`.
    Ring {
        rows: Vec<(Key, Address)>,
        head: usize,
        len: usize,
    },
}
impl KeySet {
    pub fn ring(rows: Vec<(Key, Address)>, head: usize, len: usize) -> Option<Self> {
        let cap = rows.len();
        if len > cap || (cap == 0 && head != 0) || (cap != 0 && head >= cap) {
            return None;
        }
        if (1..len).any(|i| rows[(head + i - 1) % cap].0 >= rows[(head + i) % cap].0) {
            return None;
        }
        Some(Self::Ring { rows, head, len })
    }
    fn reverse_lookup(&self, address: &Address) -> Option<Key> {
        match self {
            Self::Tree(rows) => rows
                .iter()
                .filter(|(_, a)| *a == address)
                .map(|(k, _)| *k)
                .next_back(),
            Self::Ring { rows, head, len } => (0..*len)
                .filter_map(|i| {
                    let (key, a) = &rows[(head + i) % rows.len()];
                    (a == address).then_some(*key)
                })
                .next_back(),
        }
    }
    fn contains(&self, key: &Key) -> bool {
        match self {
            Self::Tree(keys) => keys.contains_key(key),
            Self::Ring { rows, head, len } => {
                let mut low = 0;
                let mut high = *len;
                while low < high {
                    let mid = low + (high - low) / 2;
                    if rows[(head + mid) % rows.len()].0 < *key {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                low < *len && rows[(head + low) % rows.len()].0 == *key
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum History {
    Tree(BTreeMap<u64, KeySet>),
    Ring {
        rows: Vec<(u64, KeySet)>,
        head: usize,
        len: usize,
    },
}
impl History {
    pub fn ring(rows: Vec<(u64, KeySet)>, head: usize, len: usize) -> Option<Self> {
        let cap = rows.len();
        if len > cap || (cap == 0 && head != 0) || (cap != 0 && head >= cap) {
            return None;
        }
        if (1..len).any(|i| rows[(head + i - 1) % cap].0 >= rows[(head + i) % cap].0) {
            return None;
        }
        Some(Self::Ring { rows, head, len })
    }
    fn row(&self, selector: u64) -> Option<&KeySet> {
        match self {
            Self::Tree(rows) => rows.get(&selector),
            Self::Ring { rows, head, len } => {
                let mut low = 0;
                let mut high = *len;
                while low < high {
                    let mid = low + (high - low) / 2;
                    if rows[(head + mid) % rows.len()].0 < selector {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                (low < *len && rows[(head + low) % rows.len()].0 == selector)
                    .then(|| &rows[(head + low) % rows.len()].1)
            }
        }
    }
}
/// Owner's stored selector corresponds to native E+0x58. It is not the
/// incoming vote height. An absent selected row returns false after the native
/// diagnostic boundary; this model does not represent that diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub selector: u64,
    pub history: History,
}
impl Snapshot {
    /// Same selected history row; native raw tags 0x9b / 0x2b / 0x1a2.
    pub fn key_for_address(&self, address: &Address) -> Lookup {
        match self.history.row(self.selector) {
            None => Lookup::MissingHistory,
            Some(row) => row
                .reverse_lookup(address)
                .map_or(Lookup::MissingAddress, Lookup::Found),
        }
    }
    pub fn eligible(&self, key: &Key) -> bool {
        self.history
            .row(self.selector)
            .is_some_and(|row| row.contains(key))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    MissingHistory,
    MissingAddress,
    Found(Key),
}

#[cfg(test)]
mod tests {
    use super::*;
    fn k(x: u8) -> Key {
        [x; 32]
    }
    fn tree(xs: &[u8]) -> KeySet {
        KeySet::Tree(xs.iter().map(|x| (k(*x), [*x; 20])).collect())
    }
    #[test]
    fn selection_is_current_not_vote_height() {
        let mut rows = BTreeMap::new();
        rows.insert(8, tree(&[1]));
        rows.insert(9, tree(&[2]));
        let mut s = Snapshot {
            selector: 8,
            history: History::Tree(rows),
        };
        assert!(s.eligible(&k(1)));
        assert!(!s.eligible(&k(2)));
        s.selector = 9;
        assert!(!s.eligible(&k(1)));
        assert!(s.eligible(&k(2)));
        s.selector = 10;
        assert!(!s.eligible(&k(2)));
    }
    #[test]
    fn wrapped_outer_and_inner_use_full_keys() {
        let keys = KeySet::ring(
            vec![
                (k(3), [3; 20]),
                (k(4), [4; 20]),
                (k(99), [99; 20]),
                (k(1), [1; 20]),
                (k(2), [2; 20]),
            ],
            3,
            4,
        )
        .unwrap();
        let rows = vec![
            (30, tree(&[7])),
            (90, tree(&[])),
            (10, keys),
            (20, tree(&[9])),
        ];
        let mut s = Snapshot {
            selector: 10,
            history: History::ring(rows, 2, 3).unwrap(),
        };
        for x in 1..=4 {
            assert!(s.eligible(&k(x)));
        }
        assert!(!s.eligible(&k(99)));
        let mut differing = k(1);
        differing[31] = 2;
        assert!(!s.eligible(&differing));
        s.selector = 30;
        assert!(s.eligible(&k(7)));
        s.selector = 90;
        assert!(!s.eligible(&k(7)));
    }
    #[test]
    fn reverse_uses_last_matching_key_in_logical_order() {
        let set = KeySet::ring(
            vec![
                (k(3), [7; 20]),
                (k(9), [0; 20]),
                (k(1), [7; 20]),
                (k(2), [8; 20]),
            ],
            2,
            3,
        )
        .unwrap();
        let mut s = Snapshot {
            selector: 12,
            history: History::Tree([(12, set)].into_iter().collect()),
        };
        assert_eq!(s.key_for_address(&[7; 20]), Lookup::Found(k(3)));
        assert!(s.eligible(&k(3)));
        assert_eq!(s.key_for_address(&[0; 20]), Lookup::MissingAddress);
        s.selector = 13;
        assert_eq!(s.key_for_address(&[7; 20]), Lookup::MissingHistory);
    }
    #[test]
    fn tree_and_wrapped_ring_agree_for_each_selected_key() {
        let entries: Vec<_> = (0..32).map(|i| (k(i), [i % 5; 20])).collect();
        let tree = KeySet::Tree(entries.iter().copied().collect());
        for head in 0..32 {
            let mut physical = vec![(k(255), [255; 20]); 32];
            for (i, entry) in entries.iter().copied().enumerate() {
                physical[(head + i) % 32] = entry;
            }
            let ring = KeySet::ring(physical, head, 32).unwrap();
            for candidate in 0..33 {
                assert_eq!(tree.contains(&k(candidate)), ring.contains(&k(candidate)));
            }
            for address in 0..6 {
                assert_eq!(
                    tree.reverse_lookup(&[address; 20]),
                    ring.reverse_lookup(&[address; 20])
                );
            }
        }
    }
    #[test]
    fn geometry_and_empty() {
        assert!(!KeySet::ring(vec![], 0, 0).unwrap().contains(&k(0)));
        assert!(KeySet::ring(vec![], 1, 0).is_none());
        assert!(KeySet::ring(vec![(k(1), [1; 20]), (k(1), [2; 20])], 0, 2).is_none());
        assert!(History::ring(vec![(1, tree(&[])), (1, tree(&[]))], 0, 2).is_none());
        assert!(History::ring(vec![], 0, 1).is_none());
    }
}
