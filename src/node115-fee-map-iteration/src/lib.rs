//! Selected fee-map iterator and post-gate sum in node #115.
//! Native allocation, construction and map mutation are outside this model.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Row {
    pub key: [u8; 20],
    pub value: f64,
}

/// Decode the observed 32-byte ring row. Bytes 20..24 are opaque.
pub fn decode_row(bytes: &[u8; 32]) -> Row {
    let mut key = [0; 20];
    key.copy_from_slice(&bytes[..20]);
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[24..]);
    Row {
        key,
        value: f64::from_bits(u64::from_le_bytes(value)),
    }
}

/// Read valid ring entries in head-to-tail order, preserving every supplied row.
pub fn ring_rows(backing: &[[u8; 32]], head: usize, len: usize) -> Option<Vec<Row>> {
    if len > backing.len()
        || (backing.is_empty() && head != 0)
        || (!backing.is_empty() && head >= backing.len())
    {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(decode_row(&backing[(head + i) % backing.len()]));
    }
    Some(out)
}

/// Logical tree node supplied in native child/key order. Each internal node
/// must have one more child than entries. No key sorting is invented here.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub entries: Vec<Row>,
    pub children: Vec<Node>,
}

pub fn tree_rows(root: &Node) -> Option<Vec<Row>> {
    fn walk(node: &Node, out: &mut Vec<Row>) -> Option<()> {
        if node.children.is_empty() {
            out.extend_from_slice(&node.entries);
            return Some(());
        }
        if node.children.len() != node.entries.len() + 1 {
            return None;
        }
        for (i, row) in node.entries.iter().enumerate() {
            walk(&node.children[i], out)?;
            out.push(*row);
        }
        walk(node.children.last()?, out)
    }
    let mut out = Vec::new();
    walk(root, &mut out)?;
    Some(out)
}

/// Selected post-gate fold: -0.0 followed by ordered IEEE-754 additions.
/// Native `ja` rejects sums strictly above one; unordered compares do not reject.
pub fn post_gate_sum(rows: &[Row]) -> (f64, bool) {
    let mut sum = -0.0f64;
    for row in rows {
        sum += row.value;
    }
    (
        sum,
        !matches!(sum.partial_cmp(&1.0), Some(core::cmp::Ordering::Greater)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw(key: u8, value: f64) -> [u8; 32] {
        let mut r = [0x77; 32];
        r[..20].fill(key);
        r[24..].copy_from_slice(&value.to_bits().to_le_bytes());
        r
    }
    fn row(key: u8, value: f64) -> Row {
        decode_row(&raw(key, value))
    }
    #[test]
    fn wrap_preserves_order_and_opaque_padding() {
        let b = [raw(1, 0.25), raw(2, 0.5), raw(3, 0.75)];
        assert_eq!(
            ring_rows(&b, 2, 3).unwrap(),
            [row(3, 0.75), row(1, 0.25), row(2, 0.5)]
        );
        assert!(ring_rows(&b, 0, 4).is_none());
    }
    #[test]
    fn tree_interleaves_children_and_entries() {
        let n = Node {
            entries: alloc::vec![row(2, 0.2)],
            children: alloc::vec![
                Node {
                    entries: alloc::vec![row(1, 0.1)],
                    children: Vec::new()
                },
                Node {
                    entries: alloc::vec![row(3, 0.3)],
                    children: Vec::new()
                }
            ],
        };
        assert_eq!(
            tree_rows(&n).unwrap(),
            [row(1, 0.1), row(2, 0.2), row(3, 0.3)]
        );
    }
    #[test]
    fn order_matters_for_float_fold() {
        let a = [row(1, 0.5), row(2, 2f64.powi(-54)), row(3, 2f64.powi(-54))];
        let b = [a[1], a[2], a[0]];
        assert_eq!(post_gate_sum(&a).0, 0.5);
        assert_eq!(post_gate_sum(&b).0, 0.5 + f64::EPSILON / 2.0);
    }
    #[test]
    fn empty_boundary_and_unordered() {
        assert_eq!(post_gate_sum(&[]).0.to_bits(), (-0.0f64).to_bits());
        assert!(post_gate_sum(&[row(1, 1.0)]).1);
        assert!(!post_gate_sum(&[row(1, 1.01)]).1);
        assert!(post_gate_sum(&[row(1, f64::NAN)]).1);
    }
}
