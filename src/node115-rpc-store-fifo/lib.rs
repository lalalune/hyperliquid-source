//! Logical successful store mutations for node #115's two RPC cache helpers.
//! Valid maps and successful structural helpers are premises; native layouts,
//! locks, allocation failure and payload destruction are not reimplemented.
#![forbid(unsafe_code)]
use std::collections::{BTreeMap, VecDeque, btree_map::Entry};
pub type Key = [u8; 32];
pub const INITIAL_LIMIT: usize = 100_000;

#[derive(Debug)]
pub struct Store<V> {
    limit: usize,
    values: BTreeMap<Key, V>,
    order: VecDeque<Key>,
}
impl<V> Store<V> {
    /// `limit` models the descriptor's +0x40 word, not a new public RPC setting.
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            values: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
    /// Occupied keys replace without appending or moving their queue entry.
    /// Native helpers return no trace; this API likewise consumes/drops values.
    pub fn insert(&mut self, key: Key, value: V) {
        match self.values.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.insert(value);
            }
            Entry::Vacant(entry) => {
                entry.insert(value);
                self.order.push_back(key);
            }
        }
        while self.order.len() > self.limit {
            let oldest = self.order.pop_front().expect("length tested");
            self.values.remove(&oldest);
        }
    }
    /// Inspection of owned state, not a reconstructed native read endpoint.
    pub fn values(&self) -> &BTreeMap<Key, V> {
        &self.values
    }
    pub fn order(&self) -> &VecDeque<Key> {
        &self.order
    }
}
impl<V> Default for Store<V> {
    fn default() -> Self {
        Self::new(INITIAL_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(x: u64) -> Key {
        let mut key = [0; 32];
        key[24..].copy_from_slice(&x.to_be_bytes());
        key
    }
    #[test]
    fn replacement_keeps_first_insertion_position() {
        let mut s = Store::new(2);
        s.insert(key(1), 10);
        s.insert(key(2), 20);
        s.insert(key(1), 11);
        assert_eq!(s.order(), &VecDeque::from([key(1), key(2)]));
        assert_eq!(s.values()[&key(1)], 11);
        s.insert(key(3), 30);
        assert!(!s.values().contains_key(&key(1)));
        assert_eq!(s.order(), &VecDeque::from([key(2), key(3)]));
    }
    #[test]
    fn evicted_key_gets_a_new_position_on_reinsertion() {
        let mut s = Store::new(2);
        for x in [1, 2, 3, 1] {
            s.insert(key(x), x);
        }
        assert_eq!(s.order(), &VecDeque::from([key(3), key(1)]));
    }
    #[test]
    fn limit_is_key_count_including_zero_limit() {
        let mut empty = Store::new(0);
        empty.insert(key(1), [7; 0x178]);
        assert!(empty.values().is_empty());
        assert!(empty.order().is_empty());
        let mut one = Store::new(1);
        one.insert(key(1), vec![4; 1000]);
        for n in 0..100 {
            one.insert(key(1), vec![n; 1000]);
        }
        assert_eq!(one.order().len(), 1);
        one.insert(key(2), vec![5]);
        assert_eq!(one.values().len(), 1);
        assert_eq!(one.values()[&key(2)], vec![5]);
    }
    #[test]
    fn replacement_and_eviction_release_owned_payloads() {
        use std::cell::RefCell;
        use std::rc::Rc;
        struct Payload(u8, Rc<RefCell<Vec<u8>>>);
        impl Drop for Payload {
            fn drop(&mut self) {
                self.1.borrow_mut().push(self.0);
            }
        }
        let dropped = Rc::new(RefCell::new(Vec::new()));
        let mut s = Store::new(1);
        s.insert(key(1), Payload(10, dropped.clone()));
        s.insert(key(1), Payload(11, dropped.clone()));
        assert_eq!(*dropped.borrow(), [10]);
        s.insert(key(2), Payload(20, dropped.clone()));
        assert_eq!(*dropped.borrow(), [10, 11]);
        drop(s);
        assert_eq!(*dropped.borrow(), [10, 11, 20]);
    }
    #[test]
    fn sequence_oracle_uses_birth_times_without_a_queue() {
        // Distinct representation/oracle: find minimum insertion timestamp.
        // Duplicate writes change value but preserve the existing birth time.
        for limit in 0..=16 {
            let mut actual = Store::new(limit);
            let mut oracle = BTreeMap::<Key, (usize, u64)>::new();
            let mut state = 0x987654321u64;
            for time in 0..1024 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let k = key((state >> 32) % 31);
                actual.insert(k, state);
                let birth = oracle.get(&k).map_or(time, |x| x.0);
                oracle.insert(k, (birth, state));
                while oracle.len() > limit {
                    let oldest = *oracle.iter().min_by_key(|(_, v)| v.0).unwrap().0;
                    oracle.remove(&oldest);
                }
                assert_eq!(
                    *actual.values(),
                    oracle.iter().map(|(k, v)| (*k, v.1)).collect()
                );
                let mut by_age: Vec<_> = oracle.iter().collect();
                by_age.sort_by_key(|(_, v)| v.0);
                assert_eq!(
                    actual.order().iter().copied().collect::<Vec<_>>(),
                    by_age.into_iter().map(|(k, _)| *k).collect::<Vec<_>>()
                );
            }
        }
    }
    #[test]
    fn initialized_hundred_thousand_bound_is_inclusive() {
        let mut s = Store::default();
        for n in 0..INITIAL_LIMIT as u64 {
            s.insert(key(n), n);
        }
        assert_eq!(s.values().len(), INITIAL_LIMIT);
        s.insert(key(0), u64::MAX);
        assert_eq!(s.values().len(), INITIAL_LIMIT);
        s.insert(key(INITIAL_LIMIT as u64), 1);
        assert_eq!(s.values().len(), INITIAL_LIMIT);
        assert!(!s.values().contains_key(&key(0)));
        assert_eq!(s.order().front(), Some(&key(1)));
    }
}
