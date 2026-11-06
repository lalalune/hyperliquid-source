#![no_std]
//! Safe logical node115 tier selection under the frozen bounded storage premise.
//! Types and names are owned here; original ABI and global construction remain open.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowOrigin {
    Global {
        index: u32,
        byte_offset: u8,
    },
    Tree {
        node: usize,
        slot: usize,
        byte_offset: u8,
    },
    Ring {
        physical: usize,
        byte_offset: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frontier {
    Returned { words: [u64; 3], origin: RowOrigin },
    BeforeInitialize { key: u32, retained: u64 },
    BeforeDiagnostic,
}

pub struct Node<'a> {
    pub keys: &'a [u32],
    pub children: &'a [usize],
    pub fields: &'a [[u64; 3]],
}

#[derive(Clone, Copy)]
pub struct RingRow {
    pub key: u32,
    pub fields: [u64; 3],
}

/// Logical variants map to observed header MIN and valid capacity respectively;
/// this is not the original enum or a statement of its full validity domain.
pub enum Storage<'a> {
    Tree {
        root: Option<usize>,
        height: u8,
        nodes: &'a [Node<'a>],
    },
    Ring {
        head: usize,
        count: usize,
        rows: &'a [RingRow],
    },
}

pub struct Inputs<'a> {
    pub key: u32,
    pub guard: u32,
    pub retained: u64,
    pub storage: Storage<'a>,
}

fn valid_tree(nodes: &[Node<'_>], id: usize, height: u8, path: u16) -> bool {
    if id >= nodes.len() || path & (1 << id) != 0 {
        return false;
    }
    let node = &nodes[id];
    if height == 0 {
        return node.children.is_empty();
    }
    node.children.len() == node.keys.len() + 1
        && node
            .children
            .iter()
            .all(|&child| valid_tree(nodes, child, height - 1, path | (1 << id)))
}

fn valid(storage: &Storage<'_>) -> bool {
    match storage {
        Storage::Tree {
            root,
            height,
            nodes,
        } => {
            if nodes.len() > 16 || *height > 3 {
                return false;
            }
            for node in *nodes {
                if node.keys.len() > 11
                    || node.fields.len() != node.keys.len()
                    || node.keys.windows(2).any(|w| w[0] >= w[1])
                    || (!node.children.is_empty() && node.children.len() != node.keys.len() + 1)
                    || node.children.iter().any(|&id| id >= nodes.len())
                {
                    return false;
                }
            }
            root.is_none_or(|id| valid_tree(nodes, id, *height, 0))
        }
        Storage::Ring { head, count, rows } => {
            let capacity = rows.len();
            if capacity > 16
                || *count > capacity
                || (if capacity == 0 {
                    *head != 0
                } else {
                    *head >= capacity
                })
            {
                return false;
            }
            (1..*count)
                .all(|i| rows[(*head + i - 1) % capacity].key < rows[(*head + i) % capacity].key)
        }
    }
}

fn returned(words: [u64; 3], origin: RowOrigin) -> Frontier {
    Frontier::Returned { words, origin }
}

fn find_ring(key: u32, head: usize, count: usize, rows: &[RingRow]) -> Option<usize> {
    if count == 0 {
        return None;
    }
    let capacity = rows.len();
    let mut lo = 0;
    let mut hi = count;
    // Search logical sorted order. Physical conversion preserves the native
    // two-span search's successful index; its unused miss insertion index is
    // not part of the caller's observed result.
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let physical = (head + mid) % capacity;
        if rows[physical].key < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo < count && rows[(head + lo) % capacity].key == key {
        Some((head + lo) % capacity)
    } else {
        None
    }
}

/// None is our qualification-domain refusal, not a native diagnostic outcome.
/// Initializer and diagnostic helpers are never assigned a result or executed.
pub fn select(input: Inputs<'_>) -> Option<Frontier> {
    if !valid(&input.storage) {
        return None;
    }
    if input.key < 50 {
        if input.guard != 0 {
            return Some(Frontier::BeforeInitialize {
                key: input.key,
                retained: input.retained,
            });
        }
        return Some(returned(
            [1, 0, input.retained],
            RowOrigin::Global {
                index: input.key,
                byte_offset: 0,
            },
        ));
    }
    match input.storage {
        Storage::Tree {
            root,
            height,
            nodes,
        } => {
            let Some(mut id) = root else {
                return Some(Frontier::BeforeDiagnostic);
            };
            let mut depth = height;
            loop {
                let node = &nodes[id];
                let mut pos = 0;
                while pos < node.keys.len() && input.key > node.keys[pos] {
                    pos += 1;
                }
                if pos < node.keys.len() && input.key == node.keys[pos] {
                    return Some(returned(
                        node.fields[pos],
                        RowOrigin::Tree {
                            node: id,
                            slot: pos,
                            byte_offset: 24,
                        },
                    ));
                }
                if depth == 0 {
                    return Some(Frontier::BeforeDiagnostic);
                }
                depth -= 1;
                id = node.children[pos];
            }
        }
        Storage::Ring { head, count, rows } => {
            let Some(physical) = find_ring(input.key, head, count, rows) else {
                return Some(Frontier::BeforeDiagnostic);
            };
            Some(returned(
                rows[physical].fields,
                RowOrigin::Ring {
                    physical,
                    byte_offset: 32,
                },
            ))
        }
    }
}
