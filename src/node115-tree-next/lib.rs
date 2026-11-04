//! Owned arena projection of node115 next; no original Rust layout/API claim.
#[derive(Debug, Clone)]
pub struct Node {
    pub parent: Option<usize>,
    pub parent_edge: usize,
    pub keys: Vec<[u8; 20]>,
    pub values: Vec<u64>,
    pub children: Vec<usize>,
}
#[derive(Debug, Clone)]
pub struct State {
    pub words: [u64; 9],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Empty,
    ParentBoundary,
    TagBoundary,
    Item { node: usize, index: usize },
}
/// Node IDs in state are one-based; arenas/levels follow the packet preconditions.
pub fn advance(nodes: &[Node], state: &mut State) -> Outcome {
    if state.words[8] == 0 {
        return Outcome::Empty;
    }
    state.words[8] -= 1;
    if state.words[0] as u32 != 1 {
        return Outcome::TagBoundary;
    }
    let mut node;
    let mut height;
    let mut index;
    if state.words[1] != 0 {
        node = state.words[1] as usize - 1;
        height = state.words[2] as usize;
        index = state.words[3] as usize;
    } else {
        node = state.words[2] as usize - 1;
        for _ in 0..state.words[3] {
            node = nodes[node].children[0];
        }
        state.words[0] = 1;
        state.words[1] = node as u64 + 1;
        state.words[2] = 0;
        state.words[3] = 0;
        height = 0;
        index = 0;
    }
    while index >= nodes[node].keys.len() {
        let Some(parent) = nodes[node].parent else {
            return Outcome::ParentBoundary;
        };
        height += 1;
        index = nodes[node].parent_edge;
        node = parent;
    }
    let returned_node = node;
    let returned_index = index;
    let next_node;
    let next_index;
    if height == 0 {
        next_node = node;
        next_index = index + 1;
    } else {
        let mut child = nodes[node].children[index + 1];
        for _ in 1..height {
            child = nodes[child].children[0];
        }
        next_node = child;
        next_index = 0;
    }
    state.words[1] = next_node as u64 + 1;
    state.words[2] = 0;
    state.words[3] = next_index as u64;
    Outcome::Item {
        node: returned_node,
        index: returned_index,
    }
}
#[cfg(test)]
#[path = "../../research/work-items/RE-014-tree-next-115/client_fixture.rs"]
mod fixture;
#[cfg(test)]
mod tests {
    #[test]
    fn frozen_pointer_and_state_transcripts() {
        for line in
            include_str!("../../research/work-items/RE-014-tree-next-115/target-smoke.tsv").lines()
        {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 12);
            assert_eq!(super::fixture::run(&fields[..11]), fields[11]);
        }
    }
}
