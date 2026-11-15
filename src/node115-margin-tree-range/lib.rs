//! Node #115 margin-tree range boundary search and final selected-row identity.
//!
//! Independent reconstruction of 0x35c14a0 and the tree selection in
//! 0x38b5300/0x38b54b0. This is a logical memory view of valid native nodes;
//! allocation, insertion/duplicate replacement, concurrent mutation and margin
//! arithmetic are outside this crate. Synthetic addresses identify nodes, never
//! dereference native pointers. `validate` states the representation premises.

use std::collections::{BTreeMap, BTreeSet};

pub const LEAF_BYTES: usize = 0x1c4;
pub const INTERNAL_BYTES: usize = 0x228;
pub const MAX_KEYS: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Included(u64),
    Excluded(u64),
    Unbounded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    Reversed,
    EqualExcluded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    pub node: u64,
    pub index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edges {
    pub start: Edge,
    pub end: Edge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row<'a> {
    pub node: u64,
    pub index: usize,
    pub key: u64,
    pub value: &'a [u8],
}

/// Raw byte buffers indexed by synthetic nonzero native addresses.
#[derive(Debug)]
pub struct Tree {
    root: u64,
    height: usize,
    nodes: BTreeMap<u64, Vec<u8>>,
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn half(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize
}

// Native jump-table states: 0 Included, 1 Excluded, 2 first edge, 3 last edge.
// The upper search gives state 2/3 the opposite endpoint meanings.
#[derive(Clone, Copy)]
enum Search {
    Included(u64),
    Excluded(u64),
    Two,
    Three,
}

impl From<Bound> for Search {
    fn from(bound: Bound) -> Self {
        match bound {
            Bound::Included(x) => Self::Included(x),
            Bound::Excluded(x) => Self::Excluded(x),
            Bound::Unbounded => Self::Two,
        }
    }
}

fn check_bounds(start: Bound, end: Bound) -> Result<(), RangeError> {
    let (left, right) = match (start, end) {
        (Bound::Included(x) | Bound::Excluded(x), Bound::Included(y) | Bound::Excluded(y)) => {
            (x, y)
        }
        _ => return Ok(()),
    };
    if left > right {
        Err(RangeError::Reversed)
    } else if left == right && matches!((start, end), (Bound::Excluded(_), Bound::Excluded(_))) {
        Err(RangeError::EqualExcluded)
    } else {
        Ok(())
    }
}

impl Tree {
    /// The checks establish premises for safe offline observation, not a claim
    /// that the original traversal rejects malformed or duplicate-key nodes.
    pub fn validate(
        root: u64,
        height: usize,
        nodes: BTreeMap<u64, Vec<u8>>,
    ) -> Result<Self, &'static str> {
        if height > nodes.len() {
            return Err("height exceeds supplied nodes");
        }
        let tree = Self {
            root,
            height,
            nodes,
        };
        if root == 0 {
            if height != 0 {
                return Err("empty root with nonzero height");
            }
            return Ok(tree);
        }
        let mut seen = BTreeSet::new();
        tree.validate_node(root, height, None, None, None, &mut seen)?;
        Ok(tree)
    }

    fn validate_node(
        &self,
        address: u64,
        height: usize,
        parent: Option<Edge>,
        lower: Option<u64>,
        upper: Option<u64>,
        seen: &mut BTreeSet<u64>,
    ) -> Result<(), &'static str> {
        if address == 0 || !seen.insert(address) {
            return Err("missing or repeated node");
        }
        let bytes = self.nodes.get(&address).ok_or("missing node")?;
        if bytes.len()
            < if height == 0 {
                LEAF_BYTES
            } else {
                INTERNAL_BYTES
            }
        {
            return Err("short node");
        }
        let count = half(bytes, 0x1c2);
        if count > MAX_KEYS {
            return Err("node key count");
        }
        let expected_parent = parent.map_or(0, |x| x.node);
        if word(bytes, 0x160) != expected_parent {
            return Err("parent pointer");
        }
        if let Some(edge) = parent {
            if half(bytes, 0x1c0) != edge.index {
                return Err("parent edge");
            }
            if count == 0 {
                return Err("empty non-root node");
            }
        }
        let mut previous = lower;
        for index in 0..count {
            let key = word(bytes, 0x168 + index * 8);
            if previous.is_some_and(|x| x >= key) || upper.is_some_and(|x| key >= x) {
                return Err("keys not strictly ordered");
            }
            previous = Some(key);
        }
        if height != 0 {
            for index in 0..=count {
                self.validate_node(
                    word(bytes, 0x1c8 + index * 8),
                    height - 1,
                    Some(Edge {
                        node: address,
                        index,
                    }),
                    if index == 0 {
                        lower
                    } else {
                        Some(word(bytes, 0x168 + (index - 1) * 8))
                    },
                    if index == count {
                        upper
                    } else {
                        Some(word(bytes, 0x168 + index * 8))
                    },
                    seen,
                )?;
            }
        }
        Ok(())
    }

    fn bytes(&self, node: u64) -> &[u8] {
        &self.nodes[&node]
    }
    fn count(&self, node: u64) -> usize {
        half(self.bytes(node), 0x1c2)
    }
    fn key(&self, node: u64, index: usize) -> u64 {
        word(self.bytes(node), 0x168 + index * 8)
    }
    fn child(&self, node: u64, index: usize) -> u64 {
        word(self.bytes(node), 0x1c8 + index * 8)
    }

    fn lower(&self, node: u64, search: Search) -> (usize, Search) {
        let count = self.count(node);
        let key = match search {
            Search::Two => return (0, search),
            Search::Three => return (count, search),
            Search::Included(key) | Search::Excluded(key) => key,
        };
        for index in 0..count {
            match key.cmp(&self.key(node, index)) {
                std::cmp::Ordering::Less => return (index, search),
                std::cmp::Ordering::Equal => {
                    return if matches!(search, Search::Included(_)) {
                        (index, Search::Three)
                    } else {
                        (index + 1, Search::Two)
                    }
                }
                std::cmp::Ordering::Greater => (),
            }
        }
        (count, search)
    }

    fn upper(&self, node: u64, search: Search, from: usize) -> (usize, Search) {
        let count = self.count(node);
        let key = match search {
            Search::Two => return (count, search),
            Search::Three => return (from, search),
            Search::Included(key) | Search::Excluded(key) => key,
        };
        for index in from..count {
            match key.cmp(&self.key(node, index)) {
                std::cmp::Ordering::Less => return (index, search),
                std::cmp::Ordering::Equal => {
                    return if matches!(search, Search::Included(_)) {
                        (index + 1, Search::Three)
                    } else {
                        (index, Search::Two)
                    }
                }
                std::cmp::Ordering::Greater => (),
            }
        }
        (count, search)
    }

    /// Native helper's common descent followed by two separate leaf frontiers.
    /// The two returned handles are edges, not necessarily stored rows.
    pub fn range_edges(&self, start: Bound, end: Bound) -> Result<Option<Edges>, RangeError> {
        check_bounds(start, end)?;
        if self.root == 0 {
            return Ok(None);
        }
        let (mut lower, mut upper) = (Search::from(start), Search::from(end));
        let (mut node, mut height) = (self.root, self.height);
        loop {
            let (left, next_lower) = self.lower(node, lower);
            let (right, next_upper) = self.upper(node, upper, left);
            lower = next_lower;
            upper = next_upper;
            if left == right {
                if height == 0 {
                    return Ok(None);
                }
                node = self.child(node, left);
                height -= 1;
                continue;
            }
            let (mut first, mut last) = (Edge { node, index: left }, Edge { node, index: right });
            while height != 0 {
                first.node = self.child(first.node, first.index);
                last.node = self.child(last.node, last.index);
                (first.index, lower) = self.lower(first.node, lower);
                (last.index, upper) = self.upper(last.node, upper, 0);
                height -= 1;
            }
            return Ok(Some(Edges {
                start: first,
                end: last,
            }));
        }
    }

    /// The outer 0x3cd80d0 returns no range for invalid bounds instead of
    /// entering the native helper's panic arms.
    pub fn outer_range_edges(&self, start: Bound, end: Bound) -> Option<Edges> {
        self.range_edges(start, end).ok().flatten()
    }

    /// Actual 0x38b5300/0x38b54b0 tier selection: unbounded lower, included
    /// upper, followed by reverse edge traversal through parent+0x160 and
    /// parent index+0x1c0. Internal-node values are eligible results too.
    pub fn last_inclusive(&self, upper: u64) -> Option<Row<'_>> {
        let mut edge = self
            .outer_range_edges(Bound::Unbounded, Bound::Included(upper))?
            .end;
        while edge.index == 0 {
            let bytes = self.bytes(edge.node);
            edge = Edge {
                node: word(bytes, 0x160),
                index: half(bytes, 0x1c0),
            };
            assert_ne!(edge.node, 0, "valid nonempty range has a predecessor");
        }
        let index = edge.index - 1;
        Some(Row {
            node: edge.node,
            index,
            key: self.key(edge.node, index),
            value: &self.bytes(edge.node)[32 * index..32 * (index + 1)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn node(parent: u64, edge: usize, keys: &[u64], children: &[u64]) -> Vec<u8> {
        let mut bytes = vec![
            0xa5;
            if children.is_empty() {
                LEAF_BYTES
            } else {
                INTERNAL_BYTES
            }
        ];
        put(&mut bytes, 0x160, parent);
        bytes[0x1c0..0x1c2].copy_from_slice(&(edge as u16).to_le_bytes());
        bytes[0x1c2..0x1c4].copy_from_slice(&(keys.len() as u16).to_le_bytes());
        for (i, &key) in keys.iter().enumerate() {
            put(&mut bytes, 0x168 + 8 * i, key);
            bytes[32 * i..32 * (i + 1)].fill((key % 251) as u8);
        }
        for (i, &child) in children.iter().enumerate() {
            put(&mut bytes, 0x1c8 + 8 * i, child);
        }
        bytes
    }

    fn sample() -> Tree {
        Tree::validate(
            1,
            2,
            BTreeMap::from([
                (1, node(0, 0, &[40], &[2, 3])),
                (2, node(1, 0, &[10, 30], &[4, 5, 6])),
                (3, node(1, 1, &[60], &[7, 8])),
                (4, node(2, 0, &[0, 5], &[])),
                (5, node(2, 1, &[15, 20], &[])),
                (6, node(2, 2, &[35], &[])),
                (7, node(3, 0, &[45, 50], &[])),
                (8, node(3, 1, &[70, u64::MAX], &[])),
            ]),
        )
        .unwrap()
    }

    // Independent oracle: flatten the in-order value sequence and locate leaf
    // gaps by rank. It does not use the recovered boundary state machine.
    fn flatten(
        tree: &Tree,
        node: u64,
        height: usize,
        out: &mut Vec<u64>,
        gaps: &mut BTreeMap<(u64, usize), usize>,
    ) {
        let count = tree.count(node);
        for i in 0..=count {
            if height == 0 {
                gaps.insert((node, i), out.len());
            } else {
                flatten(tree, tree.child(node, i), height - 1, out, gaps);
            }
            if i < count {
                out.push(tree.key(node, i));
            }
        }
    }

    #[test]
    fn all_bound_pairs_match_flattened_ranks() {
        let tree = sample();
        let (mut keys, mut gaps) = (vec![], BTreeMap::new());
        flatten(&tree, 1, 2, &mut keys, &mut gaps);
        let probes = [
            0,
            1,
            5,
            9,
            10,
            11,
            20,
            29,
            30,
            31,
            35,
            39,
            40,
            41,
            50,
            59,
            60,
            61,
            70,
            71,
            u64::MAX,
        ];
        let bounds: Vec<_> = std::iter::once(Bound::Unbounded)
            .chain(
                probes
                    .into_iter()
                    .flat_map(|x| [Bound::Included(x), Bound::Excluded(x)]),
            )
            .collect();
        for &lower in &bounds {
            for &upper in &bounds {
                let expected: Vec<_> = keys
                    .iter()
                    .enumerate()
                    .filter(|(_, k)| {
                        (match lower {
                            Bound::Unbounded => true,
                            Bound::Included(x) => **k >= x,
                            Bound::Excluded(x) => **k > x,
                        }) && (match upper {
                            Bound::Unbounded => true,
                            Bound::Included(x) => **k <= x,
                            Bound::Excluded(x) => **k < x,
                        })
                    })
                    .map(|(i, _)| i)
                    .collect();
                let result = tree.outer_range_edges(lower, upper);
                if expected.is_empty() {
                    assert_eq!(result, None, "{lower:?} {upper:?}");
                } else {
                    let result = result.unwrap();
                    assert_eq!(
                        gaps[&(result.start.node, result.start.index)],
                        expected[0],
                        "start {lower:?} {upper:?}"
                    );
                    assert_eq!(
                        gaps[&(result.end.node, result.end.index)],
                        expected[expected.len() - 1] + 1,
                        "end {lower:?} {upper:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn selected_values_include_internal_nodes_and_exact_upper() {
        let tree = sample();
        for upper in 0..=80 {
            let expected = [0, 5, 10, 15, 20, 30, 35, 40, 45, 50, 60, 70]
                .into_iter()
                .filter(|&key| key <= upper)
                .max()
                .unwrap();
            let row = tree.last_inclusive(upper).unwrap();
            assert_eq!(row.key, expected);
            assert_eq!(row.value, &[(expected % 251) as u8; 32]);
        }
        assert_eq!(tree.last_inclusive(40).unwrap().node, 1);
        assert_eq!(tree.last_inclusive(30).unwrap().node, 2);
        assert_eq!(tree.last_inclusive(60).unwrap().node, 3);
        assert_eq!(tree.last_inclusive(u64::MAX).unwrap().key, u64::MAX);
    }

    #[test]
    fn empty_leaf_absent_root_and_invalid_ranges() {
        for tree in [
            Tree::validate(0, 0, BTreeMap::new()).unwrap(),
            Tree::validate(1, 0, BTreeMap::from([(1, node(0, 0, &[], &[]))])).unwrap(),
        ] {
            assert_eq!(tree.last_inclusive(u64::MAX), None);
        }
        let tree = Tree::validate(1, 0, BTreeMap::from([(1, node(0, 0, &[7, 9], &[]))])).unwrap();
        assert_eq!(tree.last_inclusive(6), None);
        assert_eq!(
            tree.range_edges(Bound::Excluded(7), Bound::Excluded(7)),
            Err(RangeError::EqualExcluded)
        );
        assert_eq!(
            tree.range_edges(Bound::Included(9), Bound::Included(7)),
            Err(RangeError::Reversed)
        );
        assert_eq!(
            tree.outer_range_edges(Bound::Excluded(7), Bound::Excluded(7)),
            None
        );
    }

    #[test]
    fn representation_checks_are_explicit_premises() {
        let mut tree = sample();
        put(tree.nodes.get_mut(&4).unwrap(), 0x168 + 8, 0);
        assert!(Tree::validate(1, 2, tree.nodes).is_err()); // duplicate key
        let mut tree = sample();
        tree.nodes.get_mut(&5).unwrap()[0x1c0] = 0;
        assert!(Tree::validate(1, 2, tree.nodes).is_err());
        let mut tree = sample();
        put(tree.nodes.get_mut(&2).unwrap(), 0x1c8, 1);
        assert!(Tree::validate(1, 2, tree.nodes).is_err());
    }
}
