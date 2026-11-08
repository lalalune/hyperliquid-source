#![no_std]
#![forbid(unsafe_code)]
//! Bounded model of node115 Variant A cursor search `0x35bd660`.

pub const VARIANT_A_KEY_CAPACITY: usize = 22;
pub const VARIANT_A_CHILD_CAPACITY: usize = VARIANT_A_KEY_CAPACITY + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node115VariantANode {
    pub id: u64,
    pub count: u16,
    pub keys: [u64; VARIANT_A_KEY_CAPACITY],
    pub children: [u64; VARIANT_A_CHILD_CAPACITY],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchRecord {
    pub flag: u8,
    pub node: u64,
    pub height: u64,
    pub position: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchError {
    CountOutOfRange { node: u64, count: u16 },
    NodeNotFound(u64),
}

/// Searches the measured 22-key u64 layout.
///
/// A non-exhausted scan returns flag zero at the first key greater than or equal
/// to `target`. A scan through all keys returns flag one at height zero, or
/// follows child edge `children[count]` and decrements the height.
pub fn search(
    nodes: &[Node115VariantANode],
    root: u64,
    mut height: u64,
    target: u64,
) -> Result<SearchRecord, SearchError> {
    let mut current = find_node(nodes, root)?;

    loop {
        let count = usize::from(current.count);
        if count > VARIANT_A_KEY_CAPACITY {
            return Err(SearchError::CountOutOfRange {
                node: current.id,
                count: current.count,
            });
        }

        for position in 0..count {
            if target <= current.keys[position] {
                return Ok(SearchRecord {
                    flag: 0,
                    node: current.id,
                    height,
                    position: position as u16,
                });
            }
        }

        if height == 0 {
            return Ok(SearchRecord {
                flag: 1,
                node: current.id,
                height,
                position: current.count,
            });
        }

        let next = current.children[count];
        height -= 1;
        current = find_node(nodes, next)?;
    }
}

fn find_node(nodes: &[Node115VariantANode], id: u64) -> Result<&Node115VariantANode, SearchError> {
    nodes
        .iter()
        .find(|node| node.id == id)
        .ok_or(SearchError::NodeNotFound(id))
}

#[cfg(test)]
mod tests {
    use super::{Node115VariantANode, SearchError, SearchRecord, VARIANT_A_KEY_CAPACITY, search};

    fn node(id: u64, keys: &[u64], children: &[u64]) -> Node115VariantANode {
        let mut value = Node115VariantANode {
            id,
            count: keys.len() as u16,
            keys: [0; VARIANT_A_KEY_CAPACITY],
            children: [0; 23],
        };
        value.keys[..keys.len()].copy_from_slice(keys);
        value.children[..children.len()].copy_from_slice(children);
        value
    }

    #[test]
    fn finds_equal_and_greater_keys_in_node() {
        let nodes = [node(1, &[10, 20, 30], &[0, 0, 0, 0])];
        assert_eq!(
            search(&nodes, 1, 0, 20),
            Ok(SearchRecord {
                flag: 0,
                node: 1,
                height: 0,
                position: 1,
            })
        );
        assert_eq!(
            search(&nodes, 1, 0, 25),
            Ok(SearchRecord {
                flag: 0,
                node: 1,
                height: 0,
                position: 2,
            })
        );
    }

    #[test]
    fn target_below_first_key_returns_position_zero() {
        let nodes = [node(1, &[10, 20], &[0, 0, 0])];
        assert_eq!(
            search(&nodes, 1, 0, 1),
            Ok(SearchRecord {
                flag: 0,
                node: 1,
                height: 0,
                position: 0,
            })
        );
    }

    #[test]
    fn exhausted_height_returns_flag_one_at_count() {
        let nodes = [node(1, &[10, 20, 30], &[0, 0, 0, 0])];
        assert_eq!(
            search(&nodes, 1, 0, 99),
            Ok(SearchRecord {
                flag: 1,
                node: 1,
                height: 0,
                position: 3,
            })
        );
    }

    #[test]
    fn follows_child_at_scan_position_and_decrements_height() {
        let nodes = [
            node(1, &[10, 20, 30], &[0, 0, 0, 2]),
            node(2, &[40, 50], &[0, 0, 0]),
        ];
        assert_eq!(
            search(&nodes, 1, 1, 99),
            Ok(SearchRecord {
                flag: 1,
                node: 2,
                height: 0,
                position: 2,
            })
        );
    }

    #[test]
    fn supports_the_full_22_key_capacity() {
        let mut keys = [0_u64; VARIANT_A_KEY_CAPACITY];
        for (index, key) in keys.iter_mut().enumerate() {
            *key = index as u64 * 2;
        }

        let children = [0_u64; VARIANT_A_KEY_CAPACITY + 1];
        let nodes = [node(1, &keys, &children)];
        assert_eq!(
            search(&nodes, 1, 0, 100),
            Ok(SearchRecord {
                flag: 1,
                node: 1,
                height: 0,
                position: VARIANT_A_KEY_CAPACITY as u16,
            })
        );
    }

    #[test]
    fn rejects_bad_count_and_missing_nodes() {
        let mut malformed = node(1, &[10], &[0, 0]);
        malformed.count = 23;
        assert_eq!(
            search(&[malformed], 1, 0, 10),
            Err(SearchError::CountOutOfRange { node: 1, count: 23 })
        );
        assert_eq!(
            search(&[node(1, &[10], &[0, 0])], 2, 0, 10),
            Err(SearchError::NodeNotFound(2))
        );
        assert_eq!(
            search(&[node(1, &[10], &[0, 0])], 1, 1, 99),
            Err(SearchError::NodeNotFound(0))
        );
    }
}
