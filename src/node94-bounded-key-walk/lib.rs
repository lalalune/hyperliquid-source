#![no_std]
#![forbid(unsafe_code)]

//! Stored-value projection of node #94's complete 0x1b26100..0x1b2616a leaf.

/// Stable node snapshot. IDs are opaque labels; zero means a null successor.
/// Observed pointer bits may be used as IDs, without dereferencing them here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    pub id: u64,
    pub next: u64,
    pub word_e4: u16,
    pub word_e6: u16,
}

/// New safe-API refusals, not recovered target return values or stored triples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    InvalidNodeMap,
    MissingNode(u64),
    NonterminatingCycle,
}

fn lookup(nodes: &[Node], id: u64) -> Result<&Node, Refusal> {
    nodes
        .iter()
        .find(|node| node.id == id)
        .ok_or(Refusal::MissingNode(id))
}

/// Return the exact three qwords selected for storage by the original leaf.
///
/// The map must have unique nonzero IDs; this is checked before traversal.
/// Missing successors are refused only if reached. A closing cycle edge can
/// still stop at its gate; only a cycle with no reachable stopping gate is
/// refused. The index increments modulo 2^64 and comparisons are unsigned.
///
/// This assumes stable readable original nodes and projects stored values,
/// not pointer validity, output-memory side effects, or the returned out-pointer.
/// The meanings of the two word fields and key are unknown.
pub fn raw_triple(
    nodes: &[Node],
    start: u64,
    mut index: u64,
    key: u64,
) -> Result<[u64; 3], Refusal> {
    for (i, node) in nodes.iter().enumerate() {
        if node.id == 0 || nodes[..i].iter().any(|previous| previous.id == node.id) {
            return Err(Refusal::InvalidNodeMap);
        }
    }
    let mut current = lookup(nodes, start)?;
    if key < u64::from(current.word_e6) {
        return Ok([current.id, index, key]);
    }
    // N failed nonnull edges must have closed a cycle in an N-node map.
    // The final edge's gate is evaluated before declaring nontermination.
    for _ in 0..nodes.len() {
        if current.next == 0 {
            return Ok([0, current.id, index]);
        }
        let next = lookup(nodes, current.next)?;
        let gate = current.word_e4;
        index = index.wrapping_add(1);
        if gate < next.word_e6 {
            return Ok([next.id, index, u64::from(gate)]);
        }
        current = next;
    }
    Err(Refusal::NonterminatingCycle)
}
