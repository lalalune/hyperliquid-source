//! The stake set the verifier gets from its provider, and the membership search over it.
//!
//! Layout seen by `0x4e00160`, `0x57e8bd0`, `0x595bc40` and `0x4d3e1a0`: the stake map at `+0` (tree when
//! the first word is `0x8000000000000000`, else a ring of 32 byte rows: key, stake at row `+0x18`), the
//! validator key tree at `+0x20` and the validator count word at `+0x30`.
//!
//! Flat (ring) stake maps are summed by `node115-stake-predicate`, the crate that reconstructs the same
//! saturating selected/total fold and strict `2 * total < 3 * selected` test for the flat form.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use node115_stake_predicate::{Row, predicate};

use crate::sigmap::Address;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StakeMap {
    Tree(BTreeMap<Address, u64>),
    /// `rows.len()` is the capacity; live rows are `len` rows from `head`, wrapping, sorted by key.
    Ring { rows: Vec<Row>, head: usize, len: usize },
}

impl StakeMap {
    pub fn tree(entries: impl IntoIterator<Item = (Address, u64)>) -> Self {
        StakeMap::Tree(entries.into_iter().collect())
    }

    /// `None` unless the live rows are in nondecreasing key order and `head`, `len` fit the capacity (the
    /// conditions of `node115_stake_predicate::predicate`; the native searches do not check them, so an
    /// unsorted ring is outside this model).
    pub fn ring(rows: Vec<Row>, head: usize, len: usize) -> Option<Self> {
        predicate(&rows, head, len, &[]).ok()?;
        Some(StakeMap::Ring { rows, head, len })
    }

    /// Membership as tested by the tree walk of `0x4e00160`/`0x57e8bd0` and by `0x57f54e0` (a
    /// `VecDeque::binary_search_by` over the two ring slices).
    pub fn contains(&self, key: &Address) -> bool {
        match self {
            StakeMap::Tree(m) => m.contains_key(key),
            StakeMap::Ring { rows, head, len } => {
                if *len == 0 {
                    return false;
                }
                let tail = rows.len() - head;
                let first_len = (*len).min(tail);
                let front = &rows[*head..*head + first_len];
                let back = &rows[..*len - first_len];
                let search = |s: &[Row]| s.binary_search_by(|r| r.key.cmp(key)).is_ok();
                match back.first() {
                    Some(seam) => match key.cmp(&seam.key) {
                        Ordering::Equal => true,
                        Ordering::Greater => search(back),
                        Ordering::Less => search(front),
                    },
                    None => search(front),
                }
            }
        }
    }

    /// `0x4d3e1a0`: `3 * signed > 2 * total`, both sums saturating at `u64::MAX`; `signed` adds the stake
    /// of every listed signer found in the map.
    pub fn stake_test(&self, signers: &[Address]) -> bool {
        match self {
            StakeMap::Tree(m) => {
                let signed = signers.iter().filter_map(|k| m.get(k)).fold(0u64, |a, w| a.saturating_add(*w));
                let total = m.values().fold(0u64, |a, w| a.saturating_add(*w));
                3 * u128::from(signed) > 2 * u128::from(total)
            }
            StakeMap::Ring { rows, head, len } => {
                predicate(rows, *head, *len, signers).expect("validated by StakeMap::ring").passes
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeSet {
    pub stakes: StakeMap,
    /// Keys only (`+0x20`): the count stage of the quorum looks signers up here.
    pub validators: BTreeSet<Address>,
    /// The word at `+0x30`, used as a plain multiplier in the count stage (not recomputed from the tree).
    pub validator_count: u64,
}
