#![no_std]
#![forbid(unsafe_code)]
//! Safe logical projection of the node115 DB-hub byte-key search.
//! This is not the original node layout or database-hub implementation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    ValueCount,
    ChildCount,
    UnsortedKeys,
}

/// A validated logical node from the selected native tree relation.
#[derive(Debug)]
pub struct Node<'a> {
    keys: &'a [u8],
    values: &'a [&'a [u8]],
    children: &'a [Option<&'a Node<'a>>],
}

impl<'a> Node<'a> {
    /// Construct a node with the native-observed key, value and child shape.
    ///
    /// The selected code assumes a valid sorted tree and does not independently
    /// prove these invariants. Invalid layouts are rejected by this safe API.
    pub fn new(
        keys: &'a [u8],
        values: &'a [&'a [u8]],
        children: &'a [Option<&'a Node<'a>>],
    ) -> Result<Self, LayoutError> {
        if values.len() != keys.len() {
            return Err(LayoutError::ValueCount);
        }
        if children.len() != keys.len() + 1 {
            return Err(LayoutError::ChildCount);
        }
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(LayoutError::UnsortedKeys);
        }
        Ok(Self {
            keys,
            values,
            children,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Missing,
    Found {
        value: &'a [u8],
        value_index: usize,
        nodes_visited: u64,
    },
}

/// Follow the selected byte-key scan and child descent relation.
///
/// Only the low byte of `query` enters the comparison. The root is always
/// scanned before a zero-height miss is reported, matching the observed native
/// control flow. The contract assumes an acyclic tree with the layout enforced
/// by [`Node::new`].
pub fn lookup<'a>(root: Option<&'a Node<'a>>, height: u64, query: u32) -> Lookup<'a> {
    let Some(mut node) = root else {
        return Lookup::Missing;
    };
    let byte = query as u8;
    let mut remaining_height = height;
    let mut nodes_visited = 1;

    loop {
        let found_index = node.keys.iter().position(|candidate| *candidate >= byte);
        let selected_index = found_index.unwrap_or(node.keys.len());

        if found_index.is_some() && node.keys[selected_index] == byte {
            return Lookup::Found {
                value: node.values[selected_index],
                value_index: selected_index,
                nodes_visited,
            };
        }

        if remaining_height == 0 {
            return Lookup::Missing;
        }
        remaining_height -= 1;

        let Some(child) = node.children[selected_index] else {
            return Lookup::Missing;
        };
        node = child;
        nodes_visited += 1;
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{LayoutError, Lookup, Node, lookup};
    use std::vec::Vec;

    fn key_set(case: &str) -> Vec<u8> {
        match case {
            "empty" => Vec::new(),
            "single_zero" => std::vec![0],
            "single_255" => std::vec![255],
            "edges" => std::vec![0, 127, 128, 255],
            "all_bytes" => (0..=255).collect(),
            "height_zero_hit" | "height_zero_miss" => std::vec![7, 9],
            "high_bits_low_zero" | "high_bits_low_ff" => std::vec![0, 255],
            _ => panic!("unknown case: {case}"),
        }
    }

    #[test]
    fn frozen_native_lookup_cases() {
        let text = include_str!(
            "../../research/work-items/RE-009-node115-db-hub-byte-key-lookup/target-smoke.tsv"
        );
        let mut current_case = "";
        let mut keys = Vec::new();
        let mut owned_values: Vec<Vec<u8>> = Vec::new();
        let mut rows = 0;

        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 5, "malformed case: {line}");
            if fields[0] != current_case {
                current_case = fields[0];
                keys = key_set(current_case);
                owned_values = keys.iter().map(|key| std::vec![*key]).collect();
            }

            let values: Vec<&[u8]> = owned_values.iter().map(Vec::as_slice).collect();
            let children = std::vec![None; keys.len() + 1];
            let node = Node::new(&keys, &values, &children).unwrap();
            let height: u64 = fields[1].parse().unwrap();
            let query: u32 = fields[2].parse().unwrap();
            let result = lookup(Some(&node), height, query);

            match fields[3] {
                "missing" => assert_eq!(result, Lookup::Missing, "{line}"),
                "found" => {
                    let expected_index: usize = fields[4].parse().unwrap();
                    let Lookup::Found {
                        value, value_index, ..
                    } = result
                    else {
                        panic!("expected found: {line}");
                    };
                    assert_eq!(value, &[keys[expected_index]]);
                    assert_eq!(value_index, expected_index, "{line}");
                }
                other => panic!("unknown result {other}: {line}"),
            }
            rows += 1;
        }
        assert_eq!(rows, 1284);
    }

    #[test]
    fn descends_after_nonmatching_nodes_and_ignores_high_query_bits() {
        let leaf_low = Node::new(&[1, 2], &[b"a", b"b"], &[None, None, None]).unwrap();
        let leaf_mid = Node::new(&[11, 12], &[b"c", b"d"], &[None, None, None]).unwrap();
        let leaf_high = Node::new(&[21, 22], &[b"e", b"f"], &[None, None, None]).unwrap();
        let children = [Some(&leaf_low), Some(&leaf_mid), Some(&leaf_high)];
        let root = Node::new(&[10, 20], &[b"root-a", b"root-b"], &children).unwrap();

        assert_eq!(
            lookup(Some(&root), 1, 0x10C),
            Lookup::Found {
                value: b"d",
                value_index: 1,
                nodes_visited: 2,
            }
        );
        assert_eq!(lookup(Some(&root), 0, 0x10C), Lookup::Missing);
        assert_eq!(
            lookup(Some(&root), 0, 10),
            Lookup::Found {
                value: b"root-a",
                value_index: 0,
                nodes_visited: 1,
            }
        );
    }

    #[test]
    fn rejects_non_native_node_layouts() {
        let children = [None, None, None];
        assert_eq!(
            Node::new(&[1, 2], &[b"only-one"], &children).unwrap_err(),
            LayoutError::ValueCount
        );
        assert_eq!(
            Node::new(&[1, 2], &[b"a", b"b"], &[None, None]).unwrap_err(),
            LayoutError::ChildCount
        );
        assert_eq!(
            Node::new(&[2, 1], &[b"a", b"b"], &children).unwrap_err(),
            LayoutError::UnsortedKeys
        );
        assert_eq!(
            Node::new(&[1, 1], &[b"a", b"b"], &children).unwrap_err(),
            LayoutError::UnsortedKeys
        );
    }
}
