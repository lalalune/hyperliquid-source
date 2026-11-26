//! Logical batch collection and floor scan over normalized records.
//! Known-map contents remain stable during each batch; native container geometry,
//! allocation, cleanup and signature verification are outside this model.
use std::collections::BTreeMap;
pub type Hash = [u8; 32];

/// Logical key/value view; ring keys must be strictly sorted in live order.
/// Direct construction of the public ring variant requires valid geometry;
/// `ring` checks those premises and is a host guard, not a native error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Known {
    Tree(BTreeMap<Hash, Block>),
    Ring {
        rows: Vec<(Hash, Block)>,
        head: usize,
        len: usize,
    },
}
impl Known {
    pub fn ring(rows: Vec<(Hash, Block)>, head: usize, len: usize) -> Option<Self> {
        let cap = rows.len();
        if len > cap || (cap == 0 && head != 0) || (cap != 0 && head >= cap) {
            return None;
        }
        if (1..len).any(|i| rows[(head + i - 1) % cap].0 >= rows[(head + i) % cap].0) {
            return None;
        }
        Some(Self::Ring { rows, head, len })
    }
    pub fn get(&self, key: &Hash) -> Option<&Block> {
        match self {
            Self::Tree(m) => m.get(key),
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
                (low < *len && rows[(head + low) % rows.len()].0 == *key)
                    .then(|| &rows[(head + low) % rows.len()].1)
            }
        }
    }
}

/// Native tag/round fields, projected from a valid inline block. The batch
/// gate and later floor scan deliberately use different round selections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub tag18_is_min_plus_one: bool,
    pub taga8_is_min_plus_one: bool,
    pub round50: u64,
    pub rounda0: u64,
    pub round48: u64,
    pub roundd8: u64,
}
impl Block {
    pub fn batch_round(&self) -> u64 {
        if self.tag18_is_min_plus_one {
            self.round50
        } else {
            self.rounda0
        }
    }
    pub fn floor_round(&self) -> u64 {
        if self.tag18_is_min_plus_one {
            self.round50
        } else if self.taga8_is_min_plus_one {
            self.round48
        } else {
            self.roundd8
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input<C> {
    pub hash: Hash,
    pub block: Block,
    /// None represents the native certificate capacity sentinel, not an empty vector.
    pub certificates: Option<C>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output<C> {
    pub hash: Hash,
    pub block: Option<Block>,
    pub certificates: C,
}

/// `verify` is the signed-block-wrapper boundary: false denotes its error arm.
/// It is called only for an unknown hash that meets the floor. On normal
/// success native copies the original block. Sentinel collisions are excluded.
/// Known map must not change while this runs; no native allocator effects modeled.
pub fn collect<C, F>(
    items: impl IntoIterator<Item = Input<C>>,
    known: &Known,
    floor: u64,
    mut verify: F,
) -> Vec<Output<C>>
where
    F: FnMut(&Block) -> bool,
{
    let mut output = Vec::new();
    for item in items {
        if known.get(&item.hash).is_some() {
            if let Some(certificates) = item.certificates {
                output.push(Output {
                    hash: item.hash,
                    block: None,
                    certificates,
                });
            }
        } else if item.block.batch_round().saturating_add(1) >= floor && verify(&item.block) {
            let block = item.block;
            if let Some(certificates) = item.certificates {
                output.push(Output {
                    hash: item.hash,
                    block: Some(block),
                    certificates,
                });
            }
        }
    }
    output
}
/// A missing known hash for an elided block leaves the initial/running floor unchanged.
pub fn round_floor<C>(items: &[Output<C>], known: &Known, initial: u64) -> u64 {
    items.iter().fold(initial, |floor, item| {
        item.block
            .as_ref()
            .or_else(|| known.get(&item.hash))
            .map_or(floor, |b| floor.min(b.floor_round()))
    })
}
/// Actual consumer emits None if no inline or resolvable elided block exists.
pub fn first_resolved_floor<C>(items: &[Output<C>], known: &Known) -> Option<u64> {
    let (index, first) = items.iter().enumerate().find_map(|(i, item)| {
        item.block
            .as_ref()
            .or_else(|| known.get(&item.hash))
            .map(|b| (i, b.floor_round()))
    })?;
    Some(round_floor(&items[index + 1..], known, first))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(a: bool, c: bool) -> Block {
        Block {
            tag18_is_min_plus_one: a,
            taga8_is_min_plus_one: c,
            round50: 12,
            rounda0: 20,
            round48: 3,
            roundd8: 7,
        }
    }
    fn item(n: u8, block: Block, cert: Option<u8>) -> Input<u8> {
        Input {
            hash: [n; 32],
            block,
            certificates: cert,
        }
    }
    #[test]
    fn known_elision_floor_and_order() {
        let known = Known::Tree(BTreeMap::from([([1; 32], b(false, true))]));
        let mut calls = 0;
        let result = collect(
            vec![
                item(1, b(true, false), Some(1)),
                item(2, b(false, false), Some(2)),
                item(3, b(true, false), Some(3)),
            ],
            &known,
            15,
            |_block| {
                calls += 1;
                true
            },
        );
        assert_eq!(calls, 1);
        assert_eq!(
            result.iter().map(|v| v.certificates).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(result[0].block.is_none());
        assert!(result[1].block.is_some());
        assert_eq!(round_floor(&result, &known, u64::MAX), 3);
    }
    #[test]
    fn sentinel_and_error_do_not_emit_but_verification_still_occurs() {
        let mut calls = 0;
        let known = Known::Tree(BTreeMap::new());
        let out = collect(
            vec![
                item(1, b(false, false), None),
                item(2, b(false, false), Some(2)),
            ],
            &known,
            0,
            |_v| {
                calls += 1;
                calls == 1
            },
        );
        assert_eq!(calls, 2);
        assert!(out.is_empty());
    }
    #[test]
    fn three_way_floor_differs_from_batch_and_missing_is_ignored() {
        let variants = [b(true, true), b(false, true), b(false, false)];
        assert_eq!(
            variants.iter().map(Block::floor_round).collect::<Vec<_>>(),
            vec![12, 3, 7]
        );
        assert_eq!(
            variants.iter().map(Block::batch_round).collect::<Vec<_>>(),
            vec![12, 20, 20]
        );
        let missing = Output {
            hash: [9; 32],
            block: None,
            certificates: (),
        };
        assert_eq!(
            round_floor(&[missing], &Known::Tree(BTreeMap::new()), 11),
            11
        );
    }
    #[test]
    fn ring_and_first_resolved_consumer() {
        let known = Known::ring(
            vec![
                ([3; 32], b(false, false)),
                ([9; 32], b(false, false)),
                ([1; 32], b(false, true)),
                ([2; 32], b(true, false)),
            ],
            2,
            3,
        )
        .unwrap();
        let missing = Output {
            hash: [8; 32],
            block: None,
            certificates: (),
        };
        let known_row = Output {
            hash: [1; 32],
            block: None,
            certificates: (),
        };
        let inline = Output {
            hash: [7; 32],
            block: Some(b(true, false)),
            certificates: (),
        };
        assert_eq!(first_resolved_floor::<()>(&[], &known), None);
        assert_eq!(
            first_resolved_floor(std::slice::from_ref(&missing), &known),
            None
        );
        assert_eq!(
            first_resolved_floor(&[missing, known_row, inline], &known),
            Some(3)
        );
        assert!(Known::ring(vec![], 1, 0).is_none());
    }
    #[test]
    fn saturation_and_equal_floor_pass() {
        let mut x = b(true, false);
        x.round50 = u64::MAX;
        let out = collect(
            vec![item(1, x, Some(1))],
            &Known::Tree(BTreeMap::new()),
            u64::MAX,
            |_| true,
        );
        assert_eq!(out.len(), 1);
        let out = collect(
            vec![item(1, b(true, false), Some(1))],
            &Known::Tree(BTreeMap::new()),
            13,
            |_| true,
        );
        assert_eq!(out.len(), 1);
    }
}
