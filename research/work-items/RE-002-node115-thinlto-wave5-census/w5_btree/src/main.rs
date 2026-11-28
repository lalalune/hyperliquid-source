use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn ex_bt<K: Ord + Clone, V: Clone>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: BTreeMap<K, V> = BTreeMap::new();
    m.insert(k1.clone(), v1.clone());
    m.insert(k2.clone(), v2.clone());
    let _ = core::hint::black_box(m.get(&k1));
    m.entry(k2.clone()).or_insert(v1);
    let mut m2 = m.split_off(&k2);
    m.append(&mut m2);
    let _ = core::hint::black_box(m.remove(&k1));
    let _ = core::hint::black_box(m.pop_first());
    let _ = core::hint::black_box(m.pop_last());
    let _ = core::hint::black_box(m.clone());
}

#[inline(never)]
fn ex_bt_serde<K, V>(k1: K, k2: K, v1: V, v2: V)
where
    K: Ord + Clone + serde::Serialize + serde::de::DeserializeOwned,
    V: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    ex_bt(k1.clone(), k2.clone(), v1.clone(), v2.clone());
    let mut m = BTreeMap::new();
    m.insert(k1, v1);
    m.insert(k2, v2);
    if let Ok(s) = serde_json::to_string(&m) {
        let _ = core::hint::black_box(serde_json::from_str::<BTreeMap<K, V>>(&s));
    }
    if let Ok(b) = rmp_serde::to_vec(&m) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<BTreeMap<K, V>>(&b));
    }
}

#[inline(never)]
fn ex_hm<K: Eq + Hash + Clone, V: Clone>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: HashMap<K, V> = HashMap::with_capacity(8);
    m.insert(k1.clone(), v1.clone());
    m.insert(k2.clone(), v2.clone());
    m.reserve(32);
    let _ = core::hint::black_box(m.get(&k1));
    m.entry(k2.clone()).or_insert_with(|| v1.clone());
    let _ = core::hint::black_box(m.remove(&k1));

    let mut hb: hashbrown::HashMap<K, V> = hashbrown::HashMap::with_capacity(8);
    hb.insert(k1.clone(), v1.clone());
    hb.insert(k2.clone(), v2.clone());
    hb.reserve(32);
    let _ = core::hint::black_box(hb.remove(&k1));

    let mut im: indexmap::IndexMap<K, V> = indexmap::IndexMap::with_capacity(8);
    im.insert(k1.clone(), v1.clone());
    im.insert(k2.clone(), v2.clone());
    im.reserve(32);
    let _ = core::hint::black_box(im.shift_remove(&k1));
    let _ = core::hint::black_box(im.swap_remove(&k2));
}

#[inline(never)]
fn sweep_nested_1(arg: &str) {
    let s1 = arg.to_string();
    let s2 = format!("{arg}_2");
    let a1 = [1u8; 20];
    let a2 = [2u8; 20];
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];

    macro_rules! nest {
        ($k1:expr, $k2:expr) => {
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeMap::from([(1usize, 2u64)]), BTreeMap::from([(3usize, 4u64)]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeMap::from([(1u32, 2u64)]), BTreeMap::from([(3u32, 4u64)]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeMap::from([(1u64, 2i64)]), BTreeMap::from([(3u64, 4i64)]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeMap::from([(a1, 1u64)]), BTreeMap::from([(a2, 2u64)]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeMap::from([(s1.clone(), 1u64)]), BTreeMap::from([(s2.clone(), 2u64)]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeSet::from([1usize]), BTreeSet::from([2usize]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeSet::from([a1]), BTreeSet::from([a2]));
            ex_bt_serde($k1.clone(), $k2.clone(), BTreeSet::from([s1.clone()]), BTreeSet::from([s2.clone()]));
            ex_bt_serde($k1.clone(), $k2.clone(), vec![1usize], vec![2usize]);
            ex_bt_serde($k1.clone(), $k2.clone(), vec![1u32], vec![2u32]);
            ex_bt_serde($k1.clone(), $k2.clone(), vec![a1], vec![a2]);
            ex_bt_serde($k1.clone(), $k2.clone(), vec![h1], vec![h2]);
            ex_bt_serde($k1.clone(), $k2.clone(), vec![(1u64, 2u64)], vec![(3u64, 4u64)]);
            ex_bt_serde($k1.clone(), $k2.clone(), (1u64, true), (2u64, false));
            ex_bt_serde($k1.clone(), $k2.clone(), (1i64, 2u64), (3i64, 4u64));
            ex_bt_serde($k1.clone(), $k2.clone(), (1u64, 1.5f64), (2u64, 2.5f64));
            ex_bt_serde($k1.clone(), $k2.clone(), (1.0f64, 2.0f64), (3.0f64, 4.0f64));
            ex_bt_serde($k1.clone(), $k2.clone(), (a1, 1u64), (a2, 2u64));
            ex_bt_serde($k1.clone(), $k2.clone(), (s1.clone(), 1u64), (s2.clone(), 2u64));
            ex_bt_serde($k1.clone(), $k2.clone(), Some(1u128), None);
            ex_bt_serde($k1.clone(), $k2.clone(), Some(a1), None);
            ex_bt_serde($k1.clone(), $k2.clone(), Some(h1), None);
            ex_hm($k1.clone(), $k2.clone(), vec![1usize], vec![2usize]);
            ex_hm($k1.clone(), $k2.clone(), vec![a1], vec![a2]);
            ex_hm($k1.clone(), $k2.clone(), HashSet::from([1u64]), HashSet::from([2u64]));
            ex_hm($k1.clone(), $k2.clone(), BTreeMap::from([(1u64, 2u64)]), BTreeMap::from([(3u64, 4u64)]));
            ex_hm($k1.clone(), $k2.clone(), (1u64, 2u64), (3u64, 4u64));
            ex_hm($k1.clone(), $k2.clone(), (a1, 1u64), (a2, 2u64));
        };
    }

    nest!(1u32, 2u32);
    nest!(1u64, 2u64);
    nest!(1usize, 2usize);
    nest!(a1, a2);
    nest!(h1, h2);
    nest!(s1, s2);
}

#[inline(never)]
fn sweep_sizes_2(arg: &str) {
    let s1 = arg.to_string();
    let s2 = format!("{arg}_2");
    let a1 = [1u8; 20];
    let a2 = [2u8; 20];
    let h1 = [1u8; 32];
    let h2 = [2u8; 32];

    macro_rules! sizes {
        ($k1:expr, $k2:expr) => {
            ex_bt($k1.clone(), $k2.clone(), [1u64; 7], [2u64; 7]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 9], [2u64; 9]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 11], [2u64; 11]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 13], [2u64; 13]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 14], [2u64; 14]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 15], [2u64; 15]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 18], [2u64; 18]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 20], [2u64; 20]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 24], [2u64; 24]);
            ex_bt($k1.clone(), $k2.clone(), [1u64; 32], [2u64; 32]);
            ex_bt($k1.clone(), $k2.clone(), [1u8; 40], [2u8; 40]);
            ex_bt($k1.clone(), $k2.clone(), [1u8; 48], [2u8; 48]);
            ex_bt($k1.clone(), $k2.clone(), [1u8; 64], [2u8; 64]);
            ex_bt($k1.clone(), $k2.clone(), Box::new([1u64; 8]), Box::new([2u64; 8]));
            ex_bt($k1.clone(), $k2.clone(), Arc::new(s1.clone()), Arc::new(s2.clone()));
            ex_hm($k1.clone(), $k2.clone(), [1u64; 5], [2u64; 5]);
            ex_hm($k1.clone(), $k2.clone(), [1u64; 7], [2u64; 7]);
            ex_hm($k1.clone(), $k2.clone(), [1u64; 9], [2u64; 9]);
            ex_hm($k1.clone(), $k2.clone(), [1u64; 14], [2u64; 14]);
            ex_hm($k1.clone(), $k2.clone(), [1u64; 20], [2u64; 20]);
            ex_hm($k1.clone(), $k2.clone(), [1u64; 24], [2u64; 24]);
            ex_hm($k1.clone(), $k2.clone(), [1u64; 32], [2u64; 32]);
        };
    }

    sizes!(1u32, 2u32);
    sizes!(1u64, 2u64);
    sizes!(1usize, 2usize);
    sizes!(a1, a2);
    sizes!(h1, h2);
    sizes!(s1, s2);
    sizes!((a1, 1u64), (a2, 2u64));
    sizes!((a1, 1usize), (a2, 2usize));
    sizes!((1u64, 2u64), (3u64, 4u64));
    sizes!((1usize, 2usize), (3usize, 4usize));

    // VecDeque & BinaryHeap common Hyperliquid types
    macro_rules! ex_dq_bh {
        ($a:expr, $b:expr) => {{
            let mut vd = VecDeque::with_capacity(8);
            vd.push_back($a.clone());
            vd.push_front($b.clone());
            vd.reserve(32);
            let _ = core::hint::black_box((vd.pop_front(), vd.pop_back()));
            let mut bh = BinaryHeap::new();
            bh.push($a.clone());
            bh.push($b.clone());
            let _ = core::hint::black_box(bh.pop());
            let mut v = vec![$b.clone(), $a.clone(), $b.clone(), $a.clone()];
            v.sort();
            v.sort_unstable();
            let _ = core::hint::black_box(v.binary_search(&$a));
        }};
    }
    ex_dq_bh!((1u64, 2usize), (3u64, 4usize));
    ex_dq_bh!((1i64, 2u64), (3i64, 4u64));
    ex_dq_bh!((1u64, a1), (2u64, a2));
    ex_dq_bh!((a1, 1u64), (a2, 2u64));
    ex_dq_bh!((1u64, 2u64, 3u64), (4u64, 5u64, 6u64));
    ex_dq_bh!((1u64, 2u64, 3u64, 4u64), (5u64, 6u64, 7u64, 8u64));
    ex_dq_bh!((1usize, s1.clone()), (2usize, s2.clone()));
    ex_dq_bh!((s1.clone(), a1), (s2.clone(), a2));
    ex_dq_bh!(vec![1u8], vec![2u8]);
    ex_dq_bh!(vec![1u64], vec![2u64]);
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "x".to_string());
    if arg == "__never__" {
        sweep_nested_1(&arg);
        sweep_sizes_2(&arg);
    }
}
