use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn ex_btree<K, V>(k1: K, k2: K, v1: V, v2: V)
where
    K: Ord + Clone + core::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
    V: Clone + core::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
{
    let mut m: BTreeMap<K, V> = BTreeMap::new();
    m.insert(k1.clone(), v1.clone());
    m.insert(k2.clone(), v2.clone());
    let _ = core::hint::black_box(m.get(&k1));
    if let Some(x) = m.get_mut(&k1) {
        *x = v2.clone();
    }
    m.entry(k2.clone()).or_insert_with(|| v1.clone());
    let mut m2 = m.split_off(&k2);
    m.append(&mut m2);
    let _ = core::hint::black_box(m.range(k1.clone()..=k2.clone()).count());
    let _ = core::hint::black_box(m.remove(&k1));
    let _ = core::hint::black_box(m.pop_first());
    let _ = core::hint::black_box(m.pop_last());
    let _ = core::hint::black_box(m.clone());
    let _ = core::hint::black_box(format!("{m:?}"));
    if let Ok(s) = serde_json::to_string(&m) {
        let _ = core::hint::black_box(serde_json::from_str::<BTreeMap<K, V>>(&s));
    }
    if let Ok(b) = rmp_serde::to_vec(&m) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<BTreeMap<K, V>>(&b));
    }
    if let Ok(b) = rmp_serde::to_vec_named(&m) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<BTreeMap<K, V>>(&b));
    }
    drop(m);
}

#[inline(never)]
fn ex_btree_noserde<K: Ord + Clone, V: Clone>(k1: K, k2: K, v1: V, v2: V) {
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
    drop(m);
}

#[inline(never)]
fn ex_bset<K: Ord + Clone + serde::Serialize + serde::de::DeserializeOwned>(k1: K, k2: K) {
    let mut s: BTreeSet<K> = BTreeSet::new();
    s.insert(k1.clone());
    s.insert(k2.clone());
    let _ = core::hint::black_box(s.contains(&k1));
    let mut s2 = s.split_off(&k2);
    s.append(&mut s2);
    let _ = core::hint::black_box(s.remove(&k1));
    let _ = core::hint::black_box(s.pop_first());
    let _ = core::hint::black_box(s.pop_last());
    if let Ok(j) = serde_json::to_string(&s) {
        let _ = core::hint::black_box(serde_json::from_str::<BTreeSet<K>>(&j));
    }
    if let Ok(b) = rmp_serde::to_vec(&s) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<BTreeSet<K>>(&b));
    }
}

#[inline(never)]
fn ex_hash<K, V>(k1: K, k2: K, v1: V, v2: V)
where
    K: Eq + Hash + Clone + serde::Serialize + serde::de::DeserializeOwned,
    V: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    // std::collections::HashMap
    let mut m: HashMap<K, V> = HashMap::with_capacity(8);
    m.insert(k1.clone(), v1.clone());
    m.insert(k2.clone(), v2.clone());
    m.reserve(32);
    let _ = core::hint::black_box(m.get(&k1));
    m.entry(k2.clone()).or_insert_with(|| v1.clone());
    let _ = core::hint::black_box(m.remove(&k1));
    m.shrink_to_fit();
    if let Ok(s) = serde_json::to_string(&m) {
        let _ = core::hint::black_box(serde_json::from_str::<HashMap<K, V>>(&s));
    }
    if let Ok(b) = rmp_serde::to_vec(&m) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<HashMap<K, V>>(&b));
    }
    // hashbrown 0.15.2
    let mut hb: hashbrown::HashMap<K, V> = hashbrown::HashMap::with_capacity(8);
    hb.insert(k1.clone(), v1.clone());
    hb.insert(k2.clone(), v2.clone());
    hb.reserve(32);
    let _ = core::hint::black_box(hb.get(&k1));
    let _ = core::hint::black_box(hb.remove(&k1));
    // hashbrown 0.16.1
    let mut hb16: hashbrown_16::HashMap<K, V> = hashbrown_16::HashMap::with_capacity(8);
    hb16.insert(k1.clone(), v1.clone());
    hb16.insert(k2.clone(), v2.clone());
    hb16.reserve(32);
    let _ = core::hint::black_box(hb16.get(&k1));
    let _ = core::hint::black_box(hb16.remove(&k1));
    // indexmap 2.5.0
    let mut im: indexmap::IndexMap<K, V> = indexmap::IndexMap::with_capacity(8);
    im.insert(k1.clone(), v1.clone());
    im.insert(k2.clone(), v2.clone());
    im.reserve(32);
    let _ = core::hint::black_box(im.get(&k1));
    let _ = core::hint::black_box(im.shift_remove(&k1));
    let _ = core::hint::black_box(im.swap_remove(&k2));
    if let Ok(s) = serde_json::to_string(&im) {
        let _ = core::hint::black_box(serde_json::from_str::<indexmap::IndexMap<K, V>>(&s));
    }
    if let Ok(b) = rmp_serde::to_vec(&im) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<indexmap::IndexMap<K, V>>(&b));
    }
    // std HashSet + hashbrown HashSet + IndexSet
    let mut hs: HashSet<K> = HashSet::with_capacity(8);
    hs.insert(k1.clone());
    hs.insert(k2.clone());
    hs.reserve(32);
    let _ = core::hint::black_box(hs.remove(&k1));
    let mut ims: indexmap::IndexSet<K> = indexmap::IndexSet::with_capacity(8);
    ims.insert(k1.clone());
    ims.insert(k2.clone());
    let _ = core::hint::black_box(ims.swap_remove(&k1));
}

#[inline(never)]
fn ex_hash_noserde<K: Eq + Hash + Clone, V: Clone>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: HashMap<K, V> = HashMap::with_capacity(8);
    m.insert(k1.clone(), v1.clone());
    m.insert(k2.clone(), v2.clone());
    m.reserve(32);
    let _ = core::hint::black_box(m.get(&k1));
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
    let _ = core::hint::black_box(im.swap_remove(&k1));
}

#[inline(never)]
fn ex_vec_sort<T: Ord + Clone>(a: T, b: T) {
    let mut v = vec![b.clone(), a.clone(), b.clone(), a.clone()];
    v.reserve(64);
    v.sort();
    v.sort_unstable();
    v.dedup();
    let _ = core::hint::black_box(v.binary_search(&a));
    let mut vd = VecDeque::with_capacity(8);
    vd.push_back(a.clone());
    vd.push_front(b.clone());
    vd.reserve(32);
    let _ = core::hint::black_box((vd.pop_front(), vd.pop_back()));
    let mut bh = BinaryHeap::new();
    bh.push(a);
    bh.push(b);
    let _ = core::hint::black_box(bh.pop());
}

#[inline(never)]
fn ex_vec_serde<T: Clone + serde::Serialize + serde::de::DeserializeOwned>(a: T, b: T) {
    let v = vec![a.clone(), b.clone()];
    if let Ok(s) = serde_json::to_string(&v) {
        let _ = core::hint::black_box(serde_json::from_str::<Vec<T>>(&s));
    }
    if let Ok(x) = rmp_serde::to_vec(&v) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<Vec<T>>(&x));
    }
    let opt = Some(a);
    if let Ok(s) = serde_json::to_string(&opt) {
        let _ = core::hint::black_box(serde_json::from_str::<Option<T>>(&s));
    }
    if let Ok(x) = rmp_serde::to_vec(&opt) {
        let _ = core::hint::black_box(rmp_serde::from_slice::<Option<T>>(&x));
    }
}

fn run_matrix(arg: &str) {
    let s1 = arg.to_string();
    let s2 = format!("{arg}2");
    let a1 = alloy_primitives::Address::from([1u8; 20]);
    let a2 = alloy_primitives::Address::from([2u8; 20]);
    let h1 = alloy_primitives::B256::from([1u8; 32]);
    let h2 = alloy_primitives::B256::from([2u8; 32]);
    let u1 = alloy_primitives::U256::from(1u64);
    let u2 = alloy_primitives::U256::from(2u64);
    let p_h160_1 = primitive_types::H160::from([1u8; 20]);
    let p_h160_2 = primitive_types::H160::from([2u8; 20]);
    let p_h256_1 = primitive_types::H256::from([1u8; 32]);
    let p_h256_2 = primitive_types::H256::from([2u8; 32]);
    let p_u256_1 = primitive_types::U256::from(1u64);
    let p_u256_2 = primitive_types::U256::from(2u64);
    let of1 = ordered_float::OrderedFloat(1.5f64);
    let of2 = ordered_float::OrderedFloat(2.5f64);
    let ip1 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let ip2 = IpAddr::V4(Ipv4Addr::BROADCAST);
    let sa1 = SocketAddr::new(ip1, 8080);
    let sa2 = SocketAddr::new(ip2, 8081);

    // 1. BTreeMap / HashMap / IndexMap over all Hyperliquid hot key types × value layout sizes
    macro_rules! sweep_kv {
        ($k1:expr, $k2:expr) => {
            ex_btree($k1.clone(), $k2.clone(), (), ());
            ex_btree($k1.clone(), $k2.clone(), false, true);
            ex_btree($k1.clone(), $k2.clone(), 1u8, 2u8);
            ex_btree($k1.clone(), $k2.clone(), 1u32, 2u32);
            ex_btree($k1.clone(), $k2.clone(), 1u64, 2u64);
            ex_btree($k1.clone(), $k2.clone(), 1i64, 2i64);
            ex_btree($k1.clone(), $k2.clone(), 1usize, 2usize);
            ex_btree($k1.clone(), $k2.clone(), 1u128, 2u128);
            ex_btree($k1.clone(), $k2.clone(), 1.0f64, 2.0f64);
            ex_btree($k1.clone(), $k2.clone(), s1.clone(), s2.clone());
            ex_btree($k1.clone(), $k2.clone(), vec![1u8], vec![2u8]);
            ex_btree($k1.clone(), $k2.clone(), vec![1u64], vec![2u64]);
            ex_btree($k1.clone(), $k2.clone(), vec![s1.clone()], vec![s2.clone()]);
            ex_btree($k1.clone(), $k2.clone(), (1u64, 2u64), (3u64, 4u64));
            ex_btree($k1.clone(), $k2.clone(), (1u64, 2u64, 3u64), (4u64, 5u64, 6u64));
            ex_btree($k1.clone(), $k2.clone(), [1u64; 4], [2u64; 4]);
            ex_btree($k1.clone(), $k2.clone(), [1u64; 5], [2u64; 5]);
            ex_btree($k1.clone(), $k2.clone(), [1u64; 6], [2u64; 6]);
            ex_btree($k1.clone(), $k2.clone(), [1u64; 8], [2u64; 8]);
            ex_btree($k1.clone(), $k2.clone(), [1u8; 20], [2u8; 20]);
            ex_btree($k1.clone(), $k2.clone(), [1u8; 32], [2u8; 32]);
            ex_btree($k1.clone(), $k2.clone(), Some(1u64), None);
            ex_btree($k1.clone(), $k2.clone(), Some(s1.clone()), None);
            ex_btree($k1.clone(), $k2.clone(), BTreeSet::from([1u64]), BTreeSet::from([2u64]));
            ex_btree($k1.clone(), $k2.clone(), BTreeMap::from([(1u64, 2u64)]), BTreeMap::from([(3u64, 4u64)]));
            ex_btree_noserde($k1.clone(), $k2.clone(), [1u64; 10], [2u64; 10]);
            ex_btree_noserde($k1.clone(), $k2.clone(), [1u64; 12], [2u64; 12]);
            ex_btree_noserde($k1.clone(), $k2.clone(), [1u64; 16], [2u64; 16]);
            ex_bset($k1.clone(), $k2.clone());
            ex_hash($k1.clone(), $k2.clone(), (), ());
            ex_hash($k1.clone(), $k2.clone(), 1u8, 2u8);
            ex_hash($k1.clone(), $k2.clone(), 1u32, 2u32);
            ex_hash($k1.clone(), $k2.clone(), 1u64, 2u64);
            ex_hash($k1.clone(), $k2.clone(), 1usize, 2usize);
            ex_hash($k1.clone(), $k2.clone(), 1u128, 2u128);
            ex_hash($k1.clone(), $k2.clone(), s1.clone(), s2.clone());
            ex_hash($k1.clone(), $k2.clone(), vec![1u8], vec![2u8]);
            ex_hash($k1.clone(), $k2.clone(), vec![1u64], vec![2u64]);
            ex_hash($k1.clone(), $k2.clone(), [1u64; 3], [2u64; 3]);
            ex_hash($k1.clone(), $k2.clone(), [1u64; 4], [2u64; 4]);
            ex_hash($k1.clone(), $k2.clone(), [1u64; 6], [2u64; 6]);
            ex_hash($k1.clone(), $k2.clone(), [1u64; 8], [2u64; 8]);
            ex_hash_noserde($k1.clone(), $k2.clone(), [1u64; 10], [2u64; 10]);
            ex_hash_noserde($k1.clone(), $k2.clone(), [1u64; 12], [2u64; 12]);
            ex_hash_noserde($k1.clone(), $k2.clone(), [1u64; 16], [2u64; 16]);
        };
    }

    sweep_kv!(1u8, 2u8);
    sweep_kv!(1u16, 2u16);
    sweep_kv!(1u32, 2u32);
    sweep_kv!(1u64, 2u64);
    sweep_kv!(1i64, 2i64);
    sweep_kv!(1usize, 2usize);
    sweep_kv!(1u128, 2u128);
    sweep_kv!(s1, s2);
    sweep_kv!([1u8; 20], [2u8; 20]);
    sweep_kv!([1u8; 32], [2u8; 32]);
    sweep_kv!(a1, a2);
    sweep_kv!(h1, h2);
    sweep_kv!(u1, u2);
    sweep_kv!(p_h160_1, p_h160_2);
    sweep_kv!(p_h256_1, p_h256_2);
    sweep_kv!(p_u256_1, p_u256_2);
    sweep_kv!((1u64, 2u64), (3u64, 4u64));
    sweep_kv!((1usize, 2usize), (3usize, 4usize));
    sweep_kv!((1u32, 2u64), (3u32, 4u64));
    sweep_kv!(([1u8; 20], 1u64), ([2u8; 20], 2u64));
    sweep_kv!(([1u8; 20], 1usize), ([2u8; 20], 2usize));
    sweep_kv!((a1, 1u64), (a2, 2u64));
    sweep_kv!((a1, 1usize), (a2, 2usize));
    sweep_kv!((s1.clone(), 1u64), (s2.clone(), 2u64));
    sweep_kv!((s1.clone(), s2.clone()), (s2.clone(), s1.clone()));
    sweep_kv!(of1, of2);
    sweep_kv!(ip1, ip2);
    sweep_kv!(sa1, sa2);

    // 2. Vec sort / sort_unstable / dedup / binary_search / VecDeque / BinaryHeap
    ex_vec_sort(1u8, 2u8);
    ex_vec_sort(1u16, 2u16);
    ex_vec_sort(1u32, 2u32);
    ex_vec_sort(1i32, 2i32);
    ex_vec_sort(1u64, 2u64);
    ex_vec_sort(1i64, 2i64);
    ex_vec_sort(1usize, 2usize);
    ex_vec_sort(1u128, 2u128);
    ex_vec_sort(s1.clone(), s2.clone());
    ex_vec_sort(arg, "z");
    ex_vec_sort([1u8; 20], [2u8; 20]);
    ex_vec_sort([1u8; 32], [2u8; 32]);
    ex_vec_sort(a1, a2);
    ex_vec_sort(h1, h2);
    ex_vec_sort(u1, u2);
    ex_vec_sort(p_h160_1, p_h160_2);
    ex_vec_sort(p_h256_1, p_h256_2);
    ex_vec_sort(p_u256_1, p_u256_2);
    ex_vec_sort(of1, of2);
    ex_vec_sort((1u64, 2u64), (3u64, 4u64));
    ex_vec_sort((1usize, 2u64), (3usize, 4u64));
    ex_vec_sort((1u64, 2usize), (3u64, 4usize));
    ex_vec_sort((1usize, 2usize), (3usize, 4usize));
    ex_vec_sort((1u32, 2u64), (3u32, 4u64));
    ex_vec_sort((1u64, 2u32), (3u64, 4u32));
    ex_vec_sort((1u64, of1), (2u64, of2));
    ex_vec_sort((of1, 1u64), (of2, 2u64));
    ex_vec_sort((s1.clone(), 1u64), (s2.clone(), 2u64));
    ex_vec_sort((s1.clone(), s2.clone()), (s2.clone(), s1.clone()));
    ex_vec_sort(([1u8; 20], 1u64), ([2u8; 20], 2u64));
    ex_vec_sort(([1u8; 20], 1usize), ([2u8; 20], 2usize));
    ex_vec_sort(([1u8; 20], 1u128), ([2u8; 20], 2u128));
    ex_vec_sort((1u64, [1u8; 20]), (2u64, [2u8; 20]));
    ex_vec_sort((1u64, [1u8; 32]), (2u64, [2u8; 32]));
    ex_vec_sort(([1u8; 32], 1u64), ([2u8; 32], 2u64));
    ex_vec_sort((1u64, 2u64, 3u64), (4u64, 5u64, 6u64));
    ex_vec_sort([1u64; 4], [2u64; 4]);
    ex_vec_sort([1u64; 6], [2u64; 6]);
    ex_vec_sort([1u64; 8], [2u64; 8]);

    // 3. Vec & Option serde_json + rmp_serde
    ex_vec_serde(1u8, 2u8);
    ex_vec_serde(1u32, 2u32);
    ex_vec_serde(1u64, 2u64);
    ex_vec_serde(1i64, 2i64);
    ex_vec_serde(1usize, 2usize);
    ex_vec_serde(1u128, 2u128);
    ex_vec_serde(1.5f64, 2.5f64);
    ex_vec_serde(s1.clone(), s2.clone());
    ex_vec_serde([1u8; 20], [2u8; 20]);
    ex_vec_serde([1u8; 32], [2u8; 32]);
    ex_vec_serde(a1, a2);
    ex_vec_serde(h1, h2);
    ex_vec_serde(u1, u2);
    ex_vec_serde(p_h160_1, p_h160_2);
    ex_vec_serde(p_h256_1, p_h256_2);
    ex_vec_serde(p_u256_1, p_u256_2);
    ex_vec_serde((s1.clone(), 1u64), (s2.clone(), 2u64));
    ex_vec_serde((s1.clone(), s2.clone()), (s2.clone(), s1.clone()));
    ex_vec_serde((1u64, 2u64), (3u64, 4u64));
    ex_vec_serde((a1, 1u64), (a2, 2u64));
    ex_vec_serde(serde_json::Value::Null, serde_json::Value::Bool(true));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "x".to_string());
    if arg == "__never__" {
        run_matrix(&arg);
    }
}
