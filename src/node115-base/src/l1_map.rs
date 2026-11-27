//! Node #115 `base/src/l1_map` hybrid small-`VecDeque` / large-`BTreeMap` map
//! and `Entry` / `VacantEntry` / `OccupiedEntry` API.
//!
//! Binary-grounded against 79 relocation-qualified `base/src/l1_map/entry.rs` FDEs
//! (`19,901 B`) and `.rodata` panic strings `"Out of bounds access"` (`0x5ee15f`)
//! and `"occupied entry index"` (`0x5ee173`).

use std::collections::{btree_map, BTreeMap, VecDeque};

/// Default threshold at which `L1Map` upgrades from sorted `VecDeque` to `BTreeMap`.
pub const SMALL_CAPACITY_THRESHOLD: usize = 32;

/// Hybrid sorted map backed by `VecDeque<(K, V)>` when small and `BTreeMap<K, V>` when large.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L1Map<K, V> {
    Small(VecDeque<(K, V)>),
    Large(BTreeMap<K, V>),
}

impl<K, V> Default for L1Map<K, V> {
    fn default() -> Self {
        Self::Small(VecDeque::new())
    }
}

/// Entry view into an `L1Map<K, V>` mirroring node #115 `base/src/l1_map/entry.rs`.
pub enum Entry<'a, K, V> {
    Vacant(VacantEntry<'a, K, V>),
    Occupied(OccupiedEntry<'a, K, V>),
}

/// Vacant entry view into `L1Map<K, V>`.
pub enum VacantEntry<'a, K, V> {
    Small {
        map: &'a mut VecDeque<(K, V)>,
        idx: usize,
        key: K,
    },
    Large(btree_map::VacantEntry<'a, K, V>),
}

/// Occupied entry view into `L1Map<K, V>`.
pub enum OccupiedEntry<'a, K, V> {
    Small {
        map: &'a mut VecDeque<(K, V)>,
        idx: usize,
    },
    Large(btree_map::OccupiedEntry<'a, K, V>),
}

impl<K: Ord, V> L1Map<K, V> {
    #[must_use]
    pub fn new() -> Self {
        Self::Small(VecDeque::new())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Small(deque) => deque.len(),
            Self::Large(map) => map.len(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn is_large(&self) -> bool {
        matches!(self, Self::Large(_))
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        match self {
            Self::Small(deque) => deque
                .binary_search_by(|(k, _)| k.cmp(key))
                .ok()
                .and_then(|idx| deque.get(idx).map(|(_, v)| v)),
            Self::Large(map) => map.get(key),
        }
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        match self {
            Self::Small(deque) => deque
                .binary_search_by(|(k, _)| k.cmp(key))
                .ok()
                .and_then(|idx| deque.get_mut(idx).map(|(_, v)| v)),
            Self::Large(map) => map.get_mut(key),
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.maybe_promote();
        match self {
            Self::Small(deque) => match deque.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(idx) => {
                    let slot = deque.get_mut(idx).expect("Out of bounds access");
                    Some(std::mem::replace(&mut slot.1, value))
                }
                Err(idx) => {
                    deque.insert(idx, (key, value));
                    None
                }
            },
            Self::Large(map) => map.insert(key, value),
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        match self {
            Self::Small(deque) => deque
                .binary_search_by(|(k, _)| k.cmp(key))
                .ok()
                .and_then(|idx| deque.remove(idx).map(|(_, v)| v)),
            Self::Large(map) => map.remove(key),
        }
    }

    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        self.maybe_promote();
        match self {
            Self::Small(deque) => match deque.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(idx) => Entry::Occupied(OccupiedEntry::Small { map: deque, idx }),
                Err(idx) => Entry::Vacant(VacantEntry::Small {
                    map: deque,
                    idx,
                    key,
                }),
            },
            Self::Large(map) => match map.entry(key) {
                btree_map::Entry::Vacant(v) => Entry::Vacant(VacantEntry::Large(v)),
                btree_map::Entry::Occupied(o) => Entry::Occupied(OccupiedEntry::Large(o)),
            },
        }
    }

    fn maybe_promote(&mut self) {
        if let Self::Small(deque) = self {
            if deque.len() < SMALL_CAPACITY_THRESHOLD {
                return;
            }
            let mut map = BTreeMap::new();
            while let Some((k, v)) = deque.pop_front() {
                map.insert(k, v);
            }
            *self = Self::Large(map);
        }
    }
}

impl<'a, K: Ord, V> OccupiedEntry<'a, K, V> {
    pub fn get(&self) -> &V {
        match self {
            Self::Small { map, idx } => &map.get(*idx).expect("Out of bounds access").1,
            Self::Large(entry) => entry.get(),
        }
    }

    pub fn get_mut(&mut self) -> &mut V {
        match self {
            Self::Small { map, idx } => &mut map.get_mut(*idx).expect("Out of bounds access").1,
            Self::Large(entry) => entry.get_mut(),
        }
    }

    pub fn into_mut(self) -> &'a mut V {
        match self {
            Self::Small { map, idx } => &mut map.get_mut(idx).expect("Out of bounds access").1,
            Self::Large(entry) => entry.into_mut(),
        }
    }

    pub fn remove_entry(self) -> (K, V) {
        match self {
            Self::Small { map, idx } => map.remove(idx).expect("occupied entry index"),
            Self::Large(entry) => entry.remove_entry(),
        }
    }
}

impl<'a, K: Ord, V> VacantEntry<'a, K, V> {
    pub fn insert_entry(self, value: V) -> OccupiedEntry<'a, K, V> {
        match self {
            Self::Small { map, idx, key } => {
                map.insert(idx, (key, value));
                OccupiedEntry::Small { map, idx }
            }
            Self::Large(entry) => OccupiedEntry::Large(entry.insert_entry(value)),
        }
    }
}

impl<'a, K: Ord, V> Entry<'a, K, V> {
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Self::Occupied(entry) => entry.into_mut(),
            Self::Vacant(entry) => entry.insert_entry(default).into_mut(),
        }
    }

    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        match self {
            Self::Occupied(entry) => entry.into_mut(),
            Self::Vacant(entry) => entry.insert_entry(V::default()).into_mut(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_and_large_entry_operations_match() {
        let mut map = L1Map::new();
        assert!(map.is_empty());
        assert!(!map.is_large());

        *map.entry(10u64).or_default() += 5;
        *map.entry(2u64).or_insert(7) += 3;
        *map.entry(10u64).or_default() += 1;
        assert_eq!(map.get(&10), Some(&6));
        assert_eq!(map.get(&2), Some(&10));

        if let Entry::Occupied(mut occ) = map.entry(2) {
            assert_eq!(*occ.get(), 10);
            *occ.get_mut() = 42;
            let (k, v) = occ.remove_entry();
            assert_eq!((k, v), (2, 42));
        } else {
            panic!("expected occupied entry for key 2");
        }
        assert_eq!(map.get(&2), None);

        // Promote across SMALL_CAPACITY_THRESHOLD to BTreeMap and verify Entry API again.
        for k in 0..(SMALL_CAPACITY_THRESHOLD as u64 + 8) {
            *map.entry(k).or_default() += k;
        }
        assert!(map.is_large());
        assert_eq!(map.get(&10), Some(&16));
        assert_eq!(map.get(&35), Some(&35));
        if let Entry::Occupied(occ) = map.entry(35) {
            assert_eq!(occ.remove_entry(), (35, 35));
        } else {
            panic!("expected occupied entry for key 35 in Large mode");
        }
        assert_eq!(map.get(&35), None);
    }
}
