use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hash};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[inline(never)]
fn ex_btree_map<K: Ord + Clone, V: Clone>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: BTreeMap<K, V> = BTreeMap::new();
    m.insert(black_box(k1.clone()), black_box(v1.clone()));
    m.insert(black_box(k2.clone()), black_box(v2.clone()));
    let _ = black_box(m.get(&k1));
    let _ = black_box(m.range(k1.clone()..=k2.clone()).count());
    m.entry(k1.clone()).or_insert_with(|| v2.clone());
    let mut m2 = m.split_off(&k2);
    m.append(&mut m2);
    let _ = black_box(m.remove(&k1));
    let _ = black_box(m.pop_first());
    let _ = black_box(m.pop_last());
    m.retain(|k, _| black_box(k == &k2));
    let _ = black_box(m.into_iter().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_btree_set<K: Ord + Clone>(k1: K, k2: K) {
    let mut s: BTreeSet<K> = BTreeSet::new();
    s.insert(black_box(k1.clone()));
    s.insert(black_box(k2.clone()));
    let _ = black_box(s.contains(&k1));
    let mut s2 = s.split_off(&k2);
    s.append(&mut s2);
    let _ = black_box(s.remove(&k1));
    let _ = black_box(s.pop_first());
    let _ = black_box(s.pop_last());
    let _ = black_box(s.into_iter().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_std_hashmap<K: Eq + Hash + Clone, V: Clone, S: BuildHasher + Default>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: HashMap<K, V, S> = HashMap::with_capacity_and_hasher(16, S::default());
    m.insert(black_box(k1.clone()), black_box(v1.clone()));
    m.insert(black_box(k2.clone()), black_box(v2.clone()));
    let _ = black_box(m.get(&k1));
    m.entry(k1.clone()).and_modify(|v| *v = v2.clone()).or_insert(v1.clone());
    m.reserve(64);
    m.retain(|k, _| black_box(k == &k2));
    let _ = black_box(m.remove(&k2));
    m.shrink_to_fit();
    let _ = black_box(m.into_iter().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_std_hashset<K: Eq + Hash + Clone, S: BuildHasher + Default>(k1: K, k2: K) {
    let mut s: HashSet<K, S> = HashSet::with_capacity_and_hasher(16, S::default());
    s.insert(black_box(k1.clone()));
    s.insert(black_box(k2.clone()));
    let _ = black_box(s.contains(&k1));
    s.reserve(64);
    let _ = black_box(s.remove(&k1));
    s.retain(|k| black_box(k == &k2));
    let _ = black_box(s.into_iter().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_hb15_map<K: Eq + Hash + Clone, V: Clone, S: BuildHasher + Default>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: hashbrown::HashMap<K, V, S> = hashbrown::HashMap::with_capacity_and_hasher(16, S::default());
    m.insert(black_box(k1.clone()), black_box(v1.clone()));
    m.insert(black_box(k2.clone()), black_box(v2.clone()));
    let _ = black_box(m.get(&k1));
    m.entry(k1.clone()).or_insert_with(|| v2.clone());
    m.reserve(64);
    m.retain(|k, _| black_box(k == &k2));
    let _ = black_box(m.remove(&k2));
    m.shrink_to_fit();
    let _ = black_box(m.drain().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_hb16_map<K: Eq + Hash + Clone, V: Clone, S: BuildHasher + Default>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: hashbrown_16::HashMap<K, V, S> = hashbrown_16::HashMap::with_capacity_and_hasher(16, S::default());
    m.insert(black_box(k1.clone()), black_box(v1.clone()));
    m.insert(black_box(k2.clone()), black_box(v2.clone()));
    let _ = black_box(m.get(&k1));
    m.entry(k1.clone()).or_insert_with(|| v2.clone());
    m.reserve(64);
    m.retain(|k, _| black_box(k == &k2));
    let _ = black_box(m.remove(&k2));
    let _ = black_box(m.drain().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_indexmap<K: Eq + Hash + Ord + Clone, V: Clone, S: BuildHasher + Default>(k1: K, k2: K, v1: V, v2: V) {
    let mut m: indexmap::IndexMap<K, V, S> = indexmap::IndexMap::with_capacity_and_hasher(16, S::default());
    m.insert(black_box(k1.clone()), black_box(v1.clone()));
    m.insert(black_box(k2.clone()), black_box(v2.clone()));
    let _ = black_box(m.get_full(&k1));
    m.entry(k1.clone()).or_insert_with(|| v2.clone());
    m.sort_keys();
    let _ = black_box(m.shift_remove(&k1));
    let _ = black_box(m.swap_remove(&k2));
    m.reserve(64);
    let _ = black_box(m.into_iter().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_vec_sort_deque_heap<T: Ord + Clone>(a: T, b: T, c: T) {
    let mut v = vec![black_box(c.clone()), black_box(a.clone()), black_box(b.clone())];
    v.reserve(32);
    v.sort();
    v.sort_unstable();
    let _ = black_box(v.binary_search(&b));
    v.dedup();
    v.retain(|x| black_box(x >= &a));
    let tail = v.split_off(v.len() / 2);
    v.extend(tail);
    let _ = black_box(v.drain(..).collect::<Vec<_>>());

    let mut dq = VecDeque::with_capacity(16);
    dq.push_back(a.clone());
    dq.push_front(b.clone());
    dq.push_back(c.clone());
    dq.make_contiguous().sort();
    let _ = black_box(dq.pop_front());
    let _ = black_box(dq.pop_back());

    let mut bh = BinaryHeap::new();
    bh.push(a.clone());
    bh.push(b.clone());
    bh.push(c.clone());
    let _ = black_box(bh.into_sorted_vec());

    let mut sv: smallvec::SmallVec<[T; 4]> = smallvec::SmallVec::new();
    for x in [a, b, c] {
        sv.push(x.clone());
        sv.push(x);
    }
    sv.sort_unstable();
    let _ = black_box(sv.into_vec());
}

macro_rules! ex_key_suite {
    ($k1:expr, $k2:expr, $k3:expr) => {{
        let (k1, k2, k3) = ($k1, $k2, $k3);
        ex_vec_sort_deque_heap(k1.clone(), k2.clone(), k3.clone());
        ex_btree_set(k1.clone(), k2.clone());
        ex_btree_map(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_btree_map(k1.clone(), k2.clone(), String::from("a"), String::from("b"));
        ex_btree_map(k1.clone(), k2.clone(), vec![1u8; 4], vec![2u8; 4]);
        ex_btree_map(k1.clone(), k2.clone(), 1usize, 2usize);
        ex_btree_map(k1.clone(), k2.clone(), 1u32, 2u32);
        ex_btree_map(k1.clone(), k2.clone(), true, false);
        ex_std_hashset::<_, std::collections::hash_map::RandomState>(k1.clone(), k2.clone());
        ex_std_hashset::<_, rustc_hash::FxBuildHasher>(k1.clone(), k2.clone());
        ex_std_hashset::<_, ahash::RandomState>(k1.clone(), k2.clone());
        ex_std_hashmap::<_, u64, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_std_hashmap::<_, usize, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), 1usize, 2usize);
        ex_std_hashmap::<_, String, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), "a".into(), "b".into());
        ex_std_hashmap::<_, Vec<u8>, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), vec![1], vec![2]);
        ex_std_hashmap::<_, u64, rustc_hash::FxBuildHasher>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_std_hashmap::<_, u64, ahash::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_std_hashmap::<_, u64, foldhash::fast::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_hb15_map::<_, u64, hashbrown::DefaultHashBuilder>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_hb15_map::<_, usize, hashbrown::DefaultHashBuilder>(k1.clone(), k2.clone(), 1usize, 2usize);
        ex_hb15_map::<_, String, hashbrown::DefaultHashBuilder>(k1.clone(), k2.clone(), "a".into(), "b".into());
        ex_hb15_map::<_, u64, foldhash::fast::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_hb15_map::<_, u64, ahash::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_hb16_map::<_, u64, hashbrown_16::DefaultHashBuilder>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_hb16_map::<_, String, hashbrown_16::DefaultHashBuilder>(k1.clone(), k2.clone(), "a".into(), "b".into());
        ex_indexmap::<_, u64, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
        ex_indexmap::<_, serde_json::Value, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), serde_json::json!(1), serde_json::json!("x"));
        ex_indexmap::<_, String, std::collections::hash_map::RandomState>(k1.clone(), k2.clone(), "a".into(), "b".into());
        ex_indexmap::<_, u64, foldhash::fast::RandomState>(k1.clone(), k2.clone(), 1u64, 2u64);
    }};
}

fn exercise_itoa() {
    let mut b1 = itoa::Buffer::new();
    let _ = black_box(b1.format(black_box(1234567890123456789u64)));
    let _ = black_box(b1.format(black_box(-987654321098765432i64)));
    let _ = black_box(b1.format(black_box(u128::MAX / 3)));
    let _ = black_box(b1.format(black_box(i128::MIN / 3)));
    let _ = black_box(b1.format(black_box(123456789u32)));
    let _ = black_box(b1.format(black_box(-123456789i32)));
    let _ = black_box(b1.format(black_box(65535u16)));
    let _ = black_box(b1.format(black_box(255u8)));

    let mut b04 = itoa_04::Buffer::new();
    let _ = black_box(b04.format(black_box(1234567890123456789u64)));
    let _ = black_box(b04.format(black_box(-987654321098765432i64)));
    let _ = black_box(b04.format(black_box(123456789u32)));
    let _ = black_box(b04.format(black_box(-123456789i32)));
    let mut out = Vec::new();
    let _ = itoa_04::write(&mut out, black_box(123456789u64));
    let _ = itoa_04::write(&mut out, black_box(-123456789i64));
    let _ = black_box(out);
}

fn main() {
    exercise_itoa();
    ex_key_suite!(1u8, 2u8, 3u8);
    ex_key_suite!(1u16, 2u16, 3u16);
    ex_key_suite!(1u32, 2u32, 3u32);
    ex_key_suite!(1u64, 2u64, 3u64);
    ex_key_suite!(1u128, 2u128, 3u128);
    ex_key_suite!(1usize, 2usize, 3usize);
    ex_key_suite!(-1i32, 2i32, 3i32);
    ex_key_suite!(-1i64, 2i64, 3i64);
    ex_key_suite!(String::from("a"), String::from("b"), String::from("c"));
    ex_key_suite!(vec![1u8, 2], vec![3u8, 4], vec![5u8, 6]);
    ex_key_suite!([1u8; 20], [2u8; 20], [3u8; 20]);
    ex_key_suite!([1u8; 32], [2u8; 32], [3u8; 32]);
    ex_key_suite!((1u64, 2u64), (3u64, 4u64), (5u64, 6u64));
    ex_key_suite!((1u32, 2u64), (3u32, 4u64), (5u32, 6u64));
    ex_key_suite!((1usize, 2usize), (3usize, 4usize), (5usize, 6usize));
    ex_key_suite!((String::from("a"), 1u64), (String::from("b"), 2u64), (String::from("c"), 3u64));
    ex_key_suite!((String::from("a"), String::from("x")), (String::from("b"), String::from("y")), (String::from("c"), String::from("z")));
    ex_key_suite!(bytes::Bytes::from_static(b"a"), bytes::Bytes::from_static(b"b"), bytes::Bytes::from_static(b"c"));
    ex_key_suite!(IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::BROADCAST));
    ex_key_suite!(
        SocketAddr::from(([127, 0, 0, 1], 8000)),
        SocketAddr::from(([127, 0, 0, 1], 8001)),
        SocketAddr::from(([127, 0, 0, 1], 8002))
    );
    ex_key_suite!(alloy_primitives::Address::repeat_byte(1), alloy_primitives::Address::repeat_byte(2), alloy_primitives::Address::repeat_byte(3));
    ex_key_suite!(alloy_primitives::B256::repeat_byte(1), alloy_primitives::B256::repeat_byte(2), alloy_primitives::B256::repeat_byte(3));
    ex_key_suite!(alloy_primitives::U256::from(1u64), alloy_primitives::U256::from(2u64), alloy_primitives::U256::from(3u64));
    ex_key_suite!(primitive_types::H160::repeat_byte(1), primitive_types::H160::repeat_byte(2), primitive_types::H160::repeat_byte(3));
    ex_key_suite!(primitive_types::H256::repeat_byte(1), primitive_types::H256::repeat_byte(2), primitive_types::H256::repeat_byte(3));
    ex_key_suite!(primitive_types::U256::from(1u64), primitive_types::U256::from(2u64), primitive_types::U256::from(3u64));
    ex_key_suite!(ruint::Uint::<256, 4>::from(1u64), ruint::Uint::<256, 4>::from(2u64), ruint::Uint::<256, 4>::from(3u64));
    ex_key_suite!(rust_decimal::Decimal::from(1i64), rust_decimal::Decimal::from(2i64), rust_decimal::Decimal::from(3i64));
    ex_key_suite!(ordered_float::OrderedFloat(1.0f64), ordered_float::OrderedFloat(2.0f64), ordered_float::OrderedFloat(3.0f64));
    ex_key_suite!(Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(3));
    ex_key_suite!(
        chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
        chrono::NaiveDate::from_ymd_opt(2026, 1, 2).unwrap(),
        chrono::NaiveDate::from_ymd_opt(2026, 1, 3).unwrap()
    );
    let now = Instant::now();
    ex_vec_sort_deque_heap(now, now + Duration::from_secs(1), now + Duration::from_secs(2));
    let st = SystemTime::UNIX_EPOCH;
    ex_vec_sort_deque_heap(st, st + Duration::from_secs(1), st + Duration::from_secs(2));

    // serde_json::Map with preserve_order (IndexMap<String, Value>)
    let mut jm = serde_json::Map::new();
    jm.insert("a".into(), serde_json::json!([1, 2, 3]));
    jm.insert("b".into(), serde_json::json!({"k": "v"}));
    let _ = black_box(serde_json::to_string(&jm));
    let _ = black_box(serde_json::from_str::<serde_json::Value>(black_box("{\"a\":[1,2,3],\"b\":{\"k\":\"v\"}}")));
}
