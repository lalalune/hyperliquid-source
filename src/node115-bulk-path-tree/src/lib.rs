//! Bulk construction of the node 115 directory collectors' ordered path tree.
use std::cmp::Ordering;

const CAPACITY: usize = 11;
const MIN_KEYS: usize = 5;

#[derive(Debug, Default)]
struct Node {
    keys: Vec<String>,
    children: Vec<Node>,
}

impl Node {
    fn empty_at_height(height: usize) -> Self {
        let mut node = Self::default();
        for _ in 0..height {
            node = Self {
                keys: vec![],
                children: vec![node],
            };
        }
        node
    }

    /// Return the pending separator when the entire right edge is full.
    fn append(&mut self, key: String, height: usize) -> Result<(), String> {
        let key = if let Some(right) = self.children.last_mut() {
            match right.append(key, height - 1) {
                Ok(()) => return Ok(()),
                Err(separator) => separator,
            }
        } else {
            key
        };
        if self.keys.len() == CAPACITY {
            return Err(key);
        }
        self.keys.push(key);
        if height > 0 {
            self.children.push(Self::empty_at_height(height - 1));
        }
        Ok(())
    }

    fn repair_right_edge(&mut self) {
        if self.children.is_empty() {
            return;
        }
        let pivot = self.keys.last_mut().expect("nonempty parent");
        let (right, earlier) = self.children.split_last_mut().unwrap();
        if right.keys.len() < MIN_KEYS {
            let count = MIN_KEYS - right.keys.len();
            let left = earlier.last_mut().expect("left sibling");
            let split = left.keys.len() - count;
            let mut prefix = left.keys.split_off(split + 1);
            let new_pivot = left.keys.pop().unwrap();
            prefix.push(std::mem::replace(pivot, new_pivot));
            prefix.append(&mut right.keys);
            right.keys = prefix;
            if !left.children.is_empty() {
                let mut edges = left.children.split_off(left.children.len() - count);
                edges.append(&mut right.children);
                right.children = edges;
            }
        }
        right.repair_right_edge();
    }

    fn visit(&self, visit_key: &mut impl FnMut(&str)) {
        for (i, key) in self.keys.iter().enumerate() {
            if let Some(child) = self.children.get(i) {
                child.visit(visit_key);
            }
            visit_key(key);
        }
        if let Some(right) = self.children.last() {
            right.visit(visit_key);
        }
    }
}

#[derive(Debug, Default)]
pub struct PathTree {
    root: Option<Node>,
    height: usize,
    len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OutOfOrder;

impl PathTree {
    /// The callers have already sorted these owned UTF-8 paths bytewise.
    /// The host checks that precondition. The last allocation in an equal run
    /// is the one moved into the tree.
    pub fn from_sorted(paths: Vec<String>) -> Result<Self, OutOfOrder> {
        let mut tree = Self::default();
        let mut paths = paths.into_iter();
        let Some(mut pending) = paths.next() else {
            return Ok(tree);
        };
        for next in paths {
            match pending.cmp(&next) {
                Ordering::Greater => return Err(OutOfOrder),
                Ordering::Less => tree.append(pending),
                Ordering::Equal => {}
            }
            pending = next;
        }
        tree.append(pending);
        tree.root.as_mut().unwrap().repair_right_edge();
        Ok(tree)
    }

    fn append(&mut self, key: String) {
        let root = self.root.get_or_insert_with(Node::default);
        if let Err(separator) = root.append(key, self.height) {
            let old = std::mem::take(root);
            *root = Node {
                keys: vec![separator],
                children: vec![old, Node::empty_at_height(self.height)],
            };
            self.height += 1;
        }
        self.len += 1;
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Right-edge lookup used by the startup selector.
    pub fn last(&self) -> Option<&str> {
        let mut node = self.root.as_ref()?;
        while let Some(right) = node.children.last() {
            node = right;
        }
        node.keys.last().map(String::as_str)
    }

    pub fn visit(&self, mut visit_key: impl FnMut(&str)) {
        if let Some(root) = &self.root {
            root.visit(&mut visit_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn construct(count: usize) -> PathTree {
        PathTree::from_sorted((0..count).map(|v| format!("path-{v:05}")).collect()).unwrap()
    }
    #[test]
    fn checks_native_split_and_rotation_boundaries() {
        for (n, root_keys, child_counts) in [
            (12, vec![6], vec![6, 5]),
            (13, vec![7], vec![7, 5]),
            (17, vec![11], vec![11, 5]),
            (23, vec![11], vec![11, 11]),
            (24, vec![11, 18], vec![11, 6, 5]),
        ] {
            let tree = construct(n);
            let root = tree.root.unwrap();
            let expected = root_keys
                .iter()
                .map(|x| format!("path-{x:05}"))
                .collect::<Vec<_>>();
            assert_eq!(root.keys, expected);
            assert_eq!(
                root.children
                    .iter()
                    .map(|c| c.keys.len())
                    .collect::<Vec<_>>(),
                child_counts
            );
        }
    }
    #[test]
    fn right_edge_repair_preserves_key_order_and_balances_every_level() {
        fn inspect(node: &Node, depth: usize, root: bool) {
            assert!((if root { 1 } else { MIN_KEYS }..=CAPACITY).contains(&node.keys.len()));
            if depth == 0 {
                assert!(node.children.is_empty());
            } else {
                assert_eq!(node.children.len(), node.keys.len() + 1);
                for child in &node.children {
                    inspect(child, depth - 1, false);
                }
            }
        }
        for n in [0, 1, 11, 12, 142, 143, 144, 145, 300, 1727, 1728, 4097] {
            let tree = construct(n);
            let mut all = vec![];
            tree.visit(|s| all.push(s.to_owned()));
            assert_eq!(tree.len(), n);
            assert_eq!(
                all,
                (0..n).map(|v| format!("path-{v:05}")).collect::<Vec<_>>()
            );
            assert_eq!(tree.last(), all.last().map(String::as_str));
            if let Some(root) = &tree.root {
                inspect(root, tree.height, true);
            }
        }
    }
    #[test]
    fn keeps_last_equal_allocation_and_checks_sorted_input() {
        let mut later = String::with_capacity(117);
        later.push('z');
        let retained = later.as_ptr();
        let tree = PathTree::from_sorted(vec!["a".into(), "z".into(), later]).unwrap();
        assert_eq!((tree.len(), tree.last().unwrap().as_ptr()), (2, retained));
        assert!(PathTree::from_sorted(vec!["b".into(), "a".into()]).is_err());
    }
}
