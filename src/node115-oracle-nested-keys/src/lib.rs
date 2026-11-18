//! Logical key projection of the two node 115 nested-map walker layouts.
//! Maps are valid, stable containers. Ring entries are in native logical order.
use std::collections::{BTreeMap, VecDeque, btree_map, vec_deque};

pub type Address = [u8; 20];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyPair {
    pub address: Address,
    pub key: u64,
}

pub enum Map<K, V> {
    Tree(BTreeMap<K, V>),
    Ring(VecDeque<(K, V)>),
}

enum Entries<'a, K, V> {
    Tree(btree_map::Iter<'a, K, V>),
    Ring(vec_deque::Iter<'a, (K, V)>),
}
impl<K, V> Map<K, V> {
    fn entries(&self) -> Entries<'_, K, V> {
        match self {
            Self::Tree(tree) => Entries::Tree(tree.iter()),
            Self::Ring(ring) => Entries::Ring(ring.iter()),
        }
    }
}
impl<'a, K, V> Iterator for Entries<'a, K, V> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Tree(it) => it.next(),
            Self::Ring(it) => it.next().map(|(k, v)| (k, v)),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Tree(it) => it.size_hint(),
            Self::Ring(it) => it.size_hint(),
        }
    }
}
impl<K, V> ExactSizeIterator for Entries<'_, K, V> {}

pub type Outer<V> = Map<Address, Map<u64, V>>;
type Active<'a, V> = (Address, Entries<'a, u64, V>);

/// One phase drains the remaining active rows, then each remaining outer entry,
/// then a supplemental inner iterator with its own cached address.
pub struct Phase<'a, V> {
    outer: Entries<'a, Address, Map<u64, V>>,
    active: Option<Active<'a, V>>,
    supplement: Option<Active<'a, V>>,
}
impl<'a, V> Phase<'a, V> {
    /// All inputs describe remaining entries. Active and supplemental maps may
    /// have distinct addresses even when their inner keys compare equal.
    pub fn new(
        active: Option<(Address, &'a Map<u64, V>)>,
        outer: &'a Outer<V>,
        supplement: Option<(Address, &'a Map<u64, V>)>,
    ) -> Self {
        Self {
            outer: outer.entries(),
            active: active.map(|(a, m)| (a, m.entries())),
            supplement: supplement.map(|(a, m)| (a, m.entries())),
        }
    }
}

fn next_key<V>(rows: &mut Option<Active<'_, V>>) -> Option<KeyPair> {
    let (address, it) = rows.as_mut()?;
    it.next().map(|(key, _)| KeyPair {
        address: *address,
        key: *key,
    })
}
impl<V> Iterator for Phase<'_, V> {
    type Item = KeyPair;
    fn next(&mut self) -> Option<KeyPair> {
        loop {
            if let Some(row) = next_key(&mut self.active) {
                return Some(row);
            }
            match self.outer.next() {
                Some((address, rows)) => self.active = Some((*address, rows.entries())),
                None => return next_key(&mut self.supplement),
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let a = self.active.as_ref().map_or(0, |(_, it)| it.len());
        let b = self.supplement.as_ref().map_or(0, |(_, it)| it.len());
        let upper = if self.outer.len() == 0 {
            a.checked_add(b)
        } else {
            None
        };
        (a.saturating_add(b), upper)
    }
}

/// The two layouts carry different inner values; only the keys are emitted.
/// `Chain` sums lower bounds with saturation and upper bounds with checked addition.
pub fn keys<'a, A, B>(
    first: Phase<'a, A>,
    second: Phase<'a, B>,
) -> impl Iterator<Item = KeyPair> + 'a {
    first.chain(second)
}
