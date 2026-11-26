use node115_oracle_nested_keys::{Address, KeyPair, Map, Outer, Phase, keys};
use std::collections::VecDeque;
fn address(id: u8) -> Address {
    let mut a = [0x57; 20];
    a[19] = id;
    a
}
fn pair(id: u8, key: u64) -> KeyPair {
    KeyPair {
        address: address(id),
        key,
    }
}
fn map<K: Ord + Clone, V: Clone>(rows: Vec<(K, V)>, ring: bool) -> Map<K, V> {
    if !ring {
        return Map::Tree(rows.into_iter().collect());
    }
    let mut deque = VecDeque::from(rows.clone());
    // Shift the head, then restore entries in logical order. Live entries now
    // straddle the physical wrap whenever the original buffer was full.
    if let Some(first) = deque.pop_front() {
        deque.push_back(first);
    }
    for (slot, row) in deque.iter_mut().zip(rows) {
        *slot = row;
    }
    Map::Ring(deque)
}
fn inner(values: &[u64], ring: bool) -> Map<u64, u8> {
    map(values.iter().map(|&k| (k, 211)).collect(), ring)
}
#[test]
fn partially_consumed_phases_keep_order_and_tighten_hints() {
    for mask in 0..8 {
        let first_inner = inner(&[8, 9], mask & 1 != 0);
        let empty = inner(&[], false);
        let nested = inner(&[7, 9], mask & 2 != 0);
        let groups = vec![(address(2), empty), (address(3), nested)];
        let first_outer = if mask & 4 == 0 {
            Map::Tree(groups.into_iter().collect())
        } else {
            Map::Ring(groups.into())
        };
        let tail = inner(&[u64::MAX], true);
        let other: Outer<u8> = Map::Tree(Default::default());
        let right = inner(&[1], false);
        let mut k = keys(
            Phase::new(
                Some((address(1), &first_inner)),
                &first_outer,
                Some((address(4), &tail)),
            ),
            Phase::new(None, &other, Some((address(5), &right))),
        );
        let expected = [
            pair(1, 8),
            pair(1, 9),
            pair(3, 7),
            pair(3, 9),
            pair(4, u64::MAX),
            pair(5, 1),
        ];
        for (event, hint) in expected.into_iter().zip([
            (4, None),
            (3, None),
            (2, None),
            (3, Some(3)),
            (2, Some(2)),
            (1, Some(1)),
        ]) {
            assert_eq!(k.size_hint(), hint);
            assert_eq!(k.next(), Some(event));
        }
        assert_eq!(k.next(), None);
        assert_eq!(k.size_hint(), (0, Some(0)));
        assert_eq!(k.next(), None);
    }
}
#[test]
fn all_empty_groups_and_supplements_across_phase_boundary() {
    let outer: Outer<()> = Map::Ring(vec![(address(0), Map::Tree(Default::default()))].into());
    let extra = Map::Ring(VecDeque::from([(0, ()), (u64::MAX, ())]));
    let mut k = keys(
        Phase::new(None, &outer, Some((address(8), &extra))),
        Phase::new(None, &outer, Some((address(9), &extra))),
    );
    assert_eq!(k.size_hint(), (4, None));
    assert_eq!(k.next(), Some(pair(8, 0)));
    assert_eq!(k.size_hint(), (3, None));
    assert_eq!(k.next(), Some(pair(8, u64::MAX)));
    assert_eq!(k.next(), Some(pair(9, 0)));
    assert_eq!(k.size_hint(), (1, Some(1)));
    assert_eq!(k.next(), Some(pair(9, u64::MAX)));
    assert_eq!(k.next(), None);
}
#[test]
fn equivalent_tree_and_wrapped_outer_ring_produce_same_keys() {
    for mask in 0..16 {
        let mut groups = Vec::new();
        let mut reference = Vec::new();
        for id in 0..16u8 {
            let vals: Vec<_> = (0..id % 7).map(|j| j as u64 * 257).collect();
            reference.extend(vals.iter().map(|&k| pair(id, k)));
            groups.push((address(id), inner(&vals, mask & (1 << (id % 4)) != 0)));
        }
        let mut wrapped = VecDeque::with_capacity(16);
        for _ in 0..16 {
            wrapped.push_back((address(0), inner(&[], false)));
        }
        let dummy = wrapped.pop_front().unwrap();
        wrapped.push_back(dummy);
        for (row, value) in wrapped.iter_mut().zip(groups) {
            *row = value;
        }
        assert!(!wrapped.as_slices().1.is_empty());
        let outer = Map::Ring(wrapped);
        let other: Outer<u32> = Map::Tree(Default::default());
        assert_eq!(
            keys(
                Phase::new(None, &outer, None),
                Phase::new(None, &other, None)
            )
            .collect::<Vec<_>>(),
            reference
        );
    }
}
