#![no_std]
#![forbid(unsafe_code)]
//! Safe cursor-search projection over the selected node115 u64 B-tree layout.

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
pub struct Cursor<'a> {
    pub found: bool,
    pub node: &'a Node<'a>,
    pub height: u64,
    pub position: usize,
}

pub fn search<'a>(root: Option<&'a Node<'a>>, height: u64, key: u64) -> Option<Cursor<'a>> {
    let mut node = root?;
    let mut remaining = height;
    loop {
        let position = node
            .keys
            .iter()
            .position(|candidate| *candidate >= key)
            .unwrap_or(node.keys.len());
        if position < node.keys.len() && node.keys[position] == key {
            return Some(Cursor {
                found: true,
                node,
                height: remaining,
                position,
            });
        }
        if remaining == 0 {
            return Some(Cursor {
                found: false,
                node,
                height: 0,
                position,
            });
        }
        remaining -= 1;
        node = node.children[position]?;
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{LayoutError, Node, search};
    use std::vec::Vec;

    #[test]
    fn frozen_flat_search_vectors() {
        let text = include_str!(
            "../../../../research/work-items/RE-006-node115-cursor-search/cursor-vectors.tsv"
        );
        let mut rows = 0;
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 5, "malformed vector: {line}");
            let keys: Vec<u64> = if fields[1].is_empty() {
                Vec::new()
            } else {
                fields[1].split(',').map(|v| v.parse().unwrap()).collect()
            };
            let children = std::vec![None; keys.len() + 1];
            let node = Node::new(&keys, &children).unwrap();
            let cursor = search(Some(&node), 0, fields[2].parse().unwrap()).unwrap();
            assert_eq!(cursor.found, fields[3] == "1", "{line}");
            assert_eq!(
                cursor.position,
                fields[4].parse::<usize>().unwrap(),
                "{line}"
            );
            rows += 1;
        }
        assert_eq!(rows, 1280);
    }

    #[test]
    fn descends_and_reports_final_height() {
        let leaf = Node::new(&[20, 21], &[None, None, None]).unwrap();
        let children = [None, Some(&leaf)];
        let root = Node::new(&[10], &children).unwrap();
        let cursor = search(Some(&root), 1, 21).unwrap();
        assert!(cursor.found);
        assert_eq!(cursor.height, 0);
        assert_eq!(cursor.position, 1);
    }

    #[test]
    fn rejects_invalid_layouts() {
        let children = [None; 3];
        assert_eq!(
            Node::new(&[0; 12], &[None; 13]).unwrap_err(),
            LayoutError::KeyCount
        );
        assert_eq!(
            Node::new(&[1, 2], &children[..2]).unwrap_err(),
            LayoutError::ChildCount
        );
        assert_eq!(
            Node::new(&[2, 1], &children).unwrap_err(),
            LayoutError::UnsortedKeys
        );
    }
}
