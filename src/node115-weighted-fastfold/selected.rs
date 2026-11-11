//! MIT. Conditional node115 checked first fold over actual borrowed structures.
//!
//! Constructors admit a safe value domain; their errors do not emulate native
//! malformed-state behavior. These types are not the captured layout or ABI.
use core::cmp::Ordering;

pub type Key = [u8; 20];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: Key,
    pub weight: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentLink {
    pub node: usize,
    pub edge: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub node: usize,
    pub index: usize,
}

#[derive(Debug)]
pub struct MapNode<'a> {
    pub entries: &'a [Entry],
    pub children: &'a [usize],
    pub parent: Option<ParentLink>,
}

#[derive(Debug)]
pub struct KeyNode<'a> {
    pub keys: &'a [Key],
    pub children: &'a [usize],
    pub parent: Option<ParentLink>,
}

/// Ordered constructor passes are specified in HOST-POLICY.md.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Bounds,
    Shape,
    Links,
    Topology,
    Height,
    Representation,
    MapOrder,
}

trait Node {
    const KEY_BASE: usize;
    const METADATA_START: usize;
    const CHILD_BASE: usize;
    fn len(&self) -> usize;
    fn children(&self) -> &[usize];
    fn parent(&self) -> Option<ParentLink>;
    fn key(&self, index: usize) -> &Key;
}

impl Node for MapNode<'_> {
    const KEY_BASE: usize = 0x60;
    const METADATA_START: usize = 0x13c;
    const CHILD_BASE: usize = 0x140;
    fn len(&self) -> usize {
        self.entries.len()
    }
    fn children(&self) -> &[usize] {
        self.children
    }
    fn parent(&self) -> Option<ParentLink> {
        self.parent
    }
    fn key(&self, index: usize) -> &Key {
        &self.entries[index].key
    }
}

impl Node for KeyNode<'_> {
    const KEY_BASE: usize = 8;
    const METADATA_START: usize = 0xe4;
    const CHILD_BASE: usize = 0xe8;
    fn len(&self) -> usize {
        self.keys.len()
    }
    fn children(&self) -> &[usize] {
        self.children
    }
    fn parent(&self) -> Option<ParentLink> {
        self.parent
    }
    fn key(&self, index: usize) -> &Key {
        &self.keys[index]
    }
}

// Called after bounds/reciprocity checks. A finite bound rejects cycles rather
// than silently truncating a traversal or reporting a successful empty tree.
fn depth<N: Node>(nodes: &[N], start: usize, root: usize) -> Result<usize, AdmissionError> {
    let mut at = start;
    for distance in 0..nodes.len() {
        if at == root {
            return Ok(distance);
        }
        at = nodes[at].parent().ok_or(AdmissionError::Topology)?.node;
    }
    Err(AdmissionError::Topology)
}

fn admit_tree<N: Node>(nodes: &[N], root: Option<usize>) -> Result<u64, AdmissionError> {
    // Keep passes separate: a later category never hides an earlier one.
    for node in nodes {
        if node.len() > 11
            || (!node.children().is_empty() && node.children().len() != node.len() + 1)
        {
            return Err(AdmissionError::Shape);
        }
    }
    if root.is_some_and(|r| r >= nodes.len()) {
        return Err(AdmissionError::Bounds);
    }
    for node in nodes {
        if node.children().iter().any(|&c| c >= nodes.len())
            || node.parent().is_some_and(|p| p.node >= nodes.len())
        {
            return Err(AdmissionError::Bounds);
        }
    }
    if root.is_none() != nodes.is_empty() {
        return Err(AdmissionError::Links);
    }
    for (id, node) in nodes.iter().enumerate() {
        match node.parent() {
            None if Some(id) == root => (),
            Some(p) if Some(id) != root && nodes[p.node].children().get(p.edge) == Some(&id) => (),
            _ => return Err(AdmissionError::Links),
        }
        for (edge, &child) in node.children().iter().enumerate() {
            if nodes[child].parent() != Some(ParentLink { node: id, edge }) {
                return Err(AdmissionError::Links);
            }
        }
    }
    let Some(root) = root else {
        return Ok(0);
    };
    for id in 0..nodes.len() {
        depth(nodes, id, root)?;
    }
    let mut leaf_depth = None;
    for (id, node) in nodes.iter().enumerate() {
        if node.children().is_empty() {
            let d = depth(nodes, id, root)?;
            if leaf_depth.is_some_and(|expected| expected != d) {
                return Err(AdmissionError::Height);
            }
            leaf_depth = Some(d);
        }
    }
    let mut total = 0usize;
    for node in nodes {
        total = total
            .checked_add(node.len())
            .ok_or(AdmissionError::Representation)?;
        let key_end = node
            .len()
            .checked_mul(20)
            .and_then(|n| n.checked_add(N::KEY_BASE))
            .ok_or(AdmissionError::Representation)?;
        let extent = node
            .children()
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_add(N::CHILD_BASE))
            .ok_or(AdmissionError::Representation)?;
        if key_end > N::METADATA_START || extent > isize::MAX as usize {
            return Err(AdmissionError::Representation);
        }
    }
    u64::try_from(leaf_depth.unwrap_or(0)).map_err(|_| AdmissionError::Representation)?;
    u64::try_from(total).map_err(|_| AdmissionError::Representation)
}

/// Stackless structural frontier shared by validated tree views.
#[derive(Debug, Default)]
struct Walk {
    current: Option<Position>,
    started: bool,
}

impl Walk {
    fn leftmost<N: Node>(nodes: &[N], mut at: usize) -> Position {
        while let Some(&child) = nodes[at].children().first() {
            at = child;
        }
        Position { node: at, index: 0 }
    }

    fn next<N: Node>(&mut self, nodes: &[N], root: Option<usize>) -> Option<Position> {
        if !self.started {
            self.current = root.map(|r| Self::leftmost(nodes, r));
            self.started = true;
        }
        while let Some(pos) = self.current {
            let node = &nodes[pos.node];
            if pos.index < node.len() {
                self.current = Some(if node.children().is_empty() {
                    Position {
                        node: pos.node,
                        index: pos.index + 1,
                    }
                } else {
                    Self::leftmost(nodes, node.children()[pos.index + 1])
                });
                return Some(pos);
            }
            self.current = node.parent().map(|p| Position {
                node: p.node,
                index: p.edge,
            });
        }
        None
    }
}

#[derive(Debug)]
pub struct FlatMapView<'a> {
    rows: &'a [Entry],
    head: usize,
    count: usize,
}

impl<'a> FlatMapView<'a> {
    pub fn new(rows: &'a [Entry], head: usize, count: usize) -> Result<Self, AdmissionError> {
        let capacity = rows.len();
        if count > capacity || (capacity == 0 && head != 0) || (capacity > 0 && head >= capacity) {
            return Err(AdmissionError::Bounds);
        }
        let bytes = capacity
            .checked_mul(32)
            .ok_or(AdmissionError::Representation)?;
        if bytes > isize::MAX as usize
            || u64::try_from(capacity).map_err(|_| AdmissionError::Representation)? == 1u64 << 63
        {
            return Err(AdmissionError::Representation);
        }
        head.checked_add(count)
            .ok_or(AdmissionError::Representation)?;
        let view = Self { rows, head, count };
        for i in 1..count {
            if view.at(i - 1).key > view.at(i).key {
                return Err(AdmissionError::MapOrder);
            }
        }
        Ok(view)
    }

    fn at(&self, index: usize) -> &Entry {
        let physical = self.head + index;
        &self.rows[if physical >= self.rows.len() {
            physical - self.rows.len()
        } else {
            physical
        }]
    }

    fn segment_weight(segment: &[Entry], key: &Key) -> Option<u64> {
        let end = segment.partition_point(|row| row.key <= *key);
        let candidate = end.checked_sub(1).map(|i| &segment[i])?;
        (candidate.key == *key).then_some(candidate.weight)
    }

    fn weight(&self, key: &Key) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let tail = self.count.min(self.rows.len() - self.head);
        let prefix = self.count - tail;
        if prefix != 0 {
            match self.rows[0].key.cmp(key) {
                Ordering::Equal => return Some(self.rows[0].weight),
                Ordering::Less => return Self::segment_weight(&self.rows[..prefix], key),
                Ordering::Greater => (),
            }
        }
        Self::segment_weight(&self.rows[self.head..self.head + tail], key)
    }
}

#[derive(Debug)]
pub struct TreeMapView<'a> {
    nodes: &'a [MapNode<'a>],
    root: Option<usize>,
}

impl<'a> TreeMapView<'a> {
    pub fn new(nodes: &'a [MapNode<'a>], root: Option<usize>) -> Result<Self, AdmissionError> {
        admit_tree(nodes, root)?;
        let mut walk = Walk::default();
        let mut previous: Option<&Key> = None;
        while let Some(pos) = walk.next(nodes, root) {
            let key = nodes[pos.node].key(pos.index);
            if previous.is_some_and(|p| p > key) {
                return Err(AdmissionError::MapOrder);
            }
            previous = Some(key);
        }
        Ok(Self { nodes, root })
    }

    fn weight(&self, key: &Key) -> Option<u64> {
        let mut at = self.root?;
        loop {
            let node = &self.nodes[at];
            let index = node
                .entries
                .iter()
                .position(|entry| entry.key >= *key)
                .unwrap_or(node.entries.len());
            if let Some(entry) = node.entries.get(index) {
                if entry.key == *key {
                    return Some(entry.weight);
                }
            }
            at = *node.children.get(index)?;
        }
    }
}

#[derive(Debug)]
pub enum WeightMap<'a> {
    Flat(FlatMapView<'a>),
    Tree(TreeMapView<'a>),
}

impl WeightMap<'_> {
    fn weight(&self, key: &Key) -> Option<u64> {
        match self {
            Self::Flat(map) => map.weight(key),
            Self::Tree(map) => map.weight(key),
        }
    }
}

#[derive(Debug)]
pub struct KeyTreeView<'a> {
    nodes: &'a [KeyNode<'a>],
    root: Option<usize>,
    total: u64,
}

impl<'a> KeyTreeView<'a> {
    pub fn new(nodes: &'a [KeyNode<'a>], root: Option<usize>) -> Result<Self, AdmissionError> {
        Ok(Self {
            nodes,
            root,
            total: admit_tree(nodes, root)?,
        })
    }
}

#[derive(Debug)]
pub struct KeyCursor<'a> {
    nodes: &'a [KeyNode<'a>],
    root: Option<usize>,
    walk: Walk,
    remaining: u64,
    last: Option<Position>,
}

impl<'a> KeyCursor<'a> {
    pub fn new(view: &KeyTreeView<'a>) -> Self {
        Self {
            nodes: view.nodes,
            root: view.root,
            walk: Walk::default(),
            remaining: view.total,
            last: None,
        }
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn last_yielded(&self) -> Option<Position> {
        self.last
    }

    fn next_key(&mut self) -> Option<&'a Key> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let pos = self
            .walk
            .next(self.nodes, self.root)
            .expect("validated tree has the remaining occurrence");
        self.last = Some(pos);
        Some(&self.nodes[pos.node].keys[pos.index])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldOutcome {
    Complete { sum: u64, consumed: u64 },
    Overflow { wrapped_sum: u64, consumed: u64 },
}

/// Compute the first-provider value, leaving the cursor after every consumed key.
/// Each call starts at zero. Carry retains the low64 sum and stops without
/// fetching another key. Constructor errors and native callback effects are
/// outside this operation's admitted value domain.
pub fn checked_selected_fold(map: &WeightMap<'_>, keys: &mut KeyCursor<'_>) -> FoldOutcome {
    let mut sum = 0u64;
    let mut consumed = 0u64;
    while let Some(key) = keys.next_key() {
        consumed += 1;
        if let Some(weight) = map.weight(key) {
            let (next, carry) = sum.overflowing_add(weight);
            sum = next;
            if carry {
                return FoldOutcome::Overflow {
                    wrapped_sum: sum,
                    consumed,
                };
            }
        }
    }
    FoldOutcome::Complete { sum, consumed }
}
