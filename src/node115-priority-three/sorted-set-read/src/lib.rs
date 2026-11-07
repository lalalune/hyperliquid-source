#![no_std]
#![forbid(unsafe_code)]
//! Safe standalone read-side projection for the selected node115 sorted set.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    KeyCount,
    ChildCount,
    UnsortedKeys,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Node<'a> {
    keys: &'a [u64],
    children: &'a [Option<&'a Node<'a>>],
}

impl<'a> Node<'a> {
    pub fn new(keys: &'a [u64], children: &'a [Option<&'a Node<'a>>]) -> Result<Self, LayoutError> {
        if keys.len() > 11 {
            return Err(LayoutError::KeyCount);
        }
        if children.len() != keys.len() + 1 {
            return Err(LayoutError::ChildCount);
        }
        if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(LayoutError::UnsortedKeys);
        }
        Ok(Self { keys, children })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Found<'a> {
    pub node: &'a Node<'a>,
    pub position: usize,
}

pub fn find_position<'a>(root: Option<&'a Node<'a>>, key: u64) -> Option<Found<'a>> {
    let mut node = root?;
    loop {
        let position = node
            .keys
            .iter()
            .position(|candidate| *candidate >= key)
            .unwrap_or(node.keys.len());
        if position < node.keys.len() && node.keys[position] == key {
            return Some(Found { node, position });
        }
        node = node.children[position]?;
    }
}

pub fn contains(root: Option<&Node<'_>>, key: u64) -> bool {
    find_position(root, key).is_some()
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{LayoutError, Node, contains, find_position};
    use std::vec::Vec;

    #[test]
    fn exhaustive_small_flat_sets() {
        for mask in 0u8..32 {
            let keys: Vec<u64> = (0..5).filter(|bit| mask & (1 << bit) != 0).collect();
            let children = std::vec![None; keys.len() + 1];
            let node = Node::new(&keys, &children).unwrap();
            for query in 0..=5 {
                let expected = keys.iter().position(|key| *key == query);
                assert_eq!(
                    find_position(Some(&node), query).map(|found| found.position),
                    expected
                );
                assert_eq!(contains(Some(&node), query), expected.is_some());
            }
        }
    }

    #[test]
    fn descends_to_the_matching_leaf() {
        let leaf = Node::new(&[20, 21], &[None, None, None]).unwrap();
        let children = [None, Some(&leaf)];
        let root = Node::new(&[10], &children).unwrap();
        assert_eq!(
            find_position(Some(&root), 21).map(|found| found.position),
            Some(1)
        );
        assert!(!contains(Some(&root), 19));
    }

    #[test]
    fn rejects_invalid_nodes() {
        assert_eq!(
            Node::new(&[0; 12], &[None; 13]).unwrap_err(),
            LayoutError::KeyCount
        );
        assert_eq!(
            Node::new(&[1], &[None]).unwrap_err(),
            LayoutError::ChildCount
        );
        assert_eq!(
            Node::new(&[2, 1], &[None, None, None]).unwrap_err(),
            LayoutError::UnsortedKeys
        );
    }
}
