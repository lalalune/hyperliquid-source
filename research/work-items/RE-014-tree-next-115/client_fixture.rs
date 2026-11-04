//! Input-only fixture/layout adapter, not recovered original allocation code.
use crate::{advance, Node, Outcome, State};
fn build(
    nodes: &mut Vec<Node>,
    depth: usize,
    parent: Option<usize>,
    edge: usize,
    tower: bool,
    recipe: (usize, usize, u64),
) -> usize {
    let (fan, leaf, seed) = recipe;
    let me = nodes.len();
    let n = if depth == 0 {
        leaf
    } else if tower {
        0
    } else {
        fan - 1
    };
    let keys = (0..n)
        .map(|j| std::array::from_fn(|k| (seed as u8).wrapping_add((me * 13 + j * 23 + k) as u8)))
        .collect();
    let values = (0..n)
        .map(|j| {
            seed ^ (me as u64)
                .wrapping_mul(0x9e3779b97f4a7c15)
                .wrapping_add(j as u64)
        })
        .collect();
    nodes.push(Node {
        parent,
        parent_edge: edge,
        keys,
        values,
        children: Vec::new(),
    });
    if depth != 0 {
        let children = (0..if tower { 1 } else { fan })
            .map(|i| build(nodes, depth - 1, Some(me), i, tower, recipe))
            .collect();
        nodes[me].children = children;
    }
    me
}
pub fn run(f: &[&str]) -> String {
    assert_eq!(f.len(), 11);
    let shape: u8 = f[0].parse().unwrap();
    let height: usize = f[1].parse().unwrap();
    let fan: usize = f[2].parse().unwrap();
    let leaf: usize = f[3].parse().unwrap();
    let seed: u64 = f[4].parse().unwrap();
    let tag: u64 = f[5].parse().unwrap();
    let ready: i64 = f[6].parse().unwrap();
    let index: u64 = f[7].parse().unwrap();
    let level: u64 = f[8].parse().unwrap();
    let remaining: u64 = f[9].parse().unwrap();
    let walk: u8 = f[10].parse().unwrap();
    assert!(shape <= 1 && (1..=12).contains(&fan) && leaf <= 11 && height <= 17 && walk <= 1);
    let mut nodes = Vec::new();
    if shape == 0 {
        build(&mut nodes, height, None, 0, false, (fan, leaf, seed));
    } else {
        assert!(height > 0);
        nodes.push(Node {
            parent: None,
            parent_edge: 0,
            keys: vec![std::array::from_fn(|k| (seed as u8).wrapping_add(k as u8))],
            values: vec![seed],
            children: Vec::new(),
        });
        let left = build(&mut nodes, height - 1, Some(0), 0, true, (fan, leaf, seed));
        let right = build(&mut nodes, height - 1, Some(0), 1, true, (fan, leaf, seed));
        nodes[0].children = vec![left, right];
    }
    let mut state = State {
        words: [
            tag,
            if ready < 0 { 0 } else { ready as u64 + 1 },
            if ready < 0 { 1 } else { level },
            if ready < 0 { height as u64 } else { index },
            0x111,
            0x222,
            0x333,
            0x444,
            remaining,
        ],
    };
    let limit = if walk != 0 {
        nodes.iter().map(|n| n.keys.len()).sum::<usize>() + 2
    } else {
        1
    };
    let mut transcript = Vec::new();
    for _ in 0..limit {
        let outcome = advance(&nodes, &mut state);
        let mut fields = match outcome {
            Outcome::Empty => vec!["NONE".to_string()],
            Outcome::ParentBoundary => vec!["PARENT".to_string()],
            Outcome::TagBoundary => vec!["TAG".to_string()],
            Outcome::Item { node, index } => {
                let key = nodes[node].keys[index]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                vec![
                    "ITEM".to_string(),
                    node.to_string(),
                    (0x60 + index * 20).to_string(),
                    node.to_string(),
                    (8 + index * 8).to_string(),
                    nodes[node].values[index].to_string(),
                    key,
                ]
            }
        };
        fields.extend(state.words.map(|w| w.to_string()));
        transcript.push(fields.join(","));
        if !matches!(outcome, Outcome::Item { .. }) {
            break;
        }
    }
    transcript.join(";")
}
