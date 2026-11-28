use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hash};
use std::hint::black_box;
use std::sync::{Arc, Mutex, RwLock};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[inline(never)]
fn ex_nested_btrees<K1: Ord + Clone, K2: Ord + Clone, V: Clone>(k1a: K1, k1b: K1, k2a: K2, k2b: K2, v1: V, v2: V) {
    // BTreeMap<K1, BTreeMap<K2, V>>
    let mut mm: BTreeMap<K1, BTreeMap<K2, V>> = BTreeMap::new();
    mm.entry(k1a.clone()).or_default().insert(k2a.clone(), v1.clone());
    mm.entry(k1b.clone()).or_default().insert(k2b.clone(), v2.clone());
    let _ = black_box(mm.get(&k1a).and_then(|inner| inner.get(&k2a)));
    let _ = black_box(mm.remove(&k1a));
    let _ = black_box(mm.into_iter().collect::<Vec<_>>());

    // BTreeMap<K1, BTreeSet<K2>>
    let mut ms: BTreeMap<K1, BTreeSet<K2>> = BTreeMap::new();
    ms.entry(k1a.clone()).or_default().insert(k2a.clone());
    ms.entry(k1b.clone()).or_default().insert(k2b.clone());
    let _ = black_box(ms.remove(&k1a));
    let _ = black_box(ms.into_iter().collect::<Vec<_>>());

    // BTreeMap<K1, Vec<V>>
    let mut mv: BTreeMap<K1, Vec<V>> = BTreeMap::new();
    mv.entry(k1a.clone()).or_default().push(v1.clone());
    mv.entry(k1b.clone()).or_default().push(v2.clone());
    let _ = black_box(mv.remove(&k1a));
    let _ = black_box(mv.into_iter().collect::<Vec<_>>());

    // BTreeMap<K1, VecDeque<V>>
    let mut md: BTreeMap<K1, VecDeque<V>> = BTreeMap::new();
    md.entry(k1a.clone()).or_default().push_back(v1.clone());
    md.entry(k1b.clone()).or_default().push_front(v2.clone());
    let _ = black_box(md.remove(&k1a));

    // BTreeMap<K1, Option<V>>
    let mut mo: BTreeMap<K1, Option<V>> = BTreeMap::new();
    mo.insert(k1a.clone(), Some(v1.clone()));
    mo.insert(k1b.clone(), None);
    let _ = black_box(mo.remove(&k1a));
}

#[inline(never)]
fn ex_nested_hashmaps<K1: Eq + Hash + Ord + Clone, K2: Eq + Hash + Ord + Clone, V: Clone, S: BuildHasher + Default>(
    k1a: K1, k1b: K1, k2a: K2, k2b: K2, v1: V, v2: V,
) {
    let mut hh: HashMap<K1, HashMap<K2, V, S>, S> = HashMap::with_hasher(S::default());
    hh.entry(k1a.clone()).or_insert_with(|| HashMap::with_hasher(S::default())).insert(k2a.clone(), v1.clone());
    hh.entry(k1b.clone()).or_insert_with(|| HashMap::with_hasher(S::default())).insert(k2b.clone(), v2.clone());
    let _ = black_box(hh.remove(&k1a));

    let mut hb: HashMap<K1, BTreeMap<K2, V>, S> = HashMap::with_hasher(S::default());
    hb.entry(k1a.clone()).or_default().insert(k2a.clone(), v1.clone());
    hb.entry(k1b.clone()).or_default().insert(k2b.clone(), v2.clone());
    let _ = black_box(hb.remove(&k1a));

    let mut hs: HashMap<K1, HashSet<K2, S>, S> = HashMap::with_hasher(S::default());
    hs.entry(k1a.clone()).or_insert_with(|| HashSet::with_hasher(S::default())).insert(k2a.clone());
    let _ = black_box(hs.remove(&k1a));

    let mut hv: HashMap<K1, Vec<V>, S> = HashMap::with_hasher(S::default());
    hv.entry(k1a.clone()).or_default().push(v1.clone());
    hv.entry(k1b.clone()).or_default().push(v2.clone());
    let _ = black_box(hv.remove(&k1a));

    // IndexMap nested
    let mut im: indexmap::IndexMap<K1, indexmap::IndexMap<K2, V, S>, S> = indexmap::IndexMap::with_hasher(S::default());
    im.entry(k1a.clone()).or_insert_with(|| indexmap::IndexMap::with_hasher(S::default())).insert(k2a.clone(), v1.clone());
    let _ = black_box(im.shift_remove(&k1a));

    let mut imv: indexmap::IndexMap<K1, Vec<V>, S> = indexmap::IndexMap::with_hasher(S::default());
    imv.entry(k1a.clone()).or_default().push(v1.clone());
    let _ = black_box(imv.swap_remove(&k1a));

    // hashbrown 0.15.2 nested
    let mut br: hashbrown::HashMap<K1, Vec<V>, S> = hashbrown::HashMap::with_hasher(S::default());
    br.entry(k1a.clone()).or_default().push(v1.clone());
    let _ = black_box(br.remove(&k1a));
}

#[inline(never)]
fn ex_nested_vecs<T: Ord + Clone>(a: T, b: T) {
    let mut vv: Vec<Vec<T>> = vec![vec![a.clone(), b.clone()], vec![b.clone()]];
    vv.sort();
    vv.sort_unstable();
    let _ = black_box(vv.pop());
    let mut vo: Vec<Option<T>> = vec![Some(a.clone()), None, Some(b.clone())];
    vo.sort();
    let _ = black_box(vo);
    let mut vp: Vec<(usize, T)> = vec![(1, a.clone()), (0, b.clone())];
    vp.sort_unstable();
    let _ = black_box(vp);
    let mut vq: Vec<(u64, T)> = vec![(2, a.clone()), (1, b.clone())];
    vq.sort_unstable();
    let _ = black_box(vq);
    let mu: Arc<Mutex<Vec<T>>> = Arc::new(Mutex::new(vec![a.clone()]));
    mu.lock().unwrap().push(b.clone());
    let rw: Arc<RwLock<BTreeMap<usize, T>>> = Arc::new(RwLock::new(BTreeMap::new()));
    rw.write().unwrap().insert(1, a);
    let _ = black_box((mu, rw));
}

fn ex_rocksdb_multithreaded() {
    if black_box(false) {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![rocksdb::ColumnFamilyDescriptor::new("default", opts.clone())];
        if let Ok(db) = rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf_descriptors(&opts, "/tmp/nonexistent_mt", cfs) {
            let _ = db.put(b"k", b"v");
            let _ = black_box(db.get(b"k"));
            let _ = black_box(db.multi_get([b"k"]));
            let _ = db.delete(b"k");
            let mut it = db.iterator(rocksdb::IteratorMode::Start);
            let _ = black_box(it.next());
            let mut raw = db.raw_iterator();
            raw.seek(b"k");
            let _ = black_box((raw.key(), raw.value()));
            let _ = db.create_cf("c1", &opts);
            let _ = db.drop_cf("c1");
        }
    }
}

fn main() {
    ex_rocksdb_multithreaded();
    type R = std::collections::hash_map::RandomState;
    type F = foldhash::fast::RandomState;
    type A = ahash::RandomState;
    type X = rustc_hash::FxBuildHasher;

    let addr1 = alloy_primitives::Address::repeat_byte(1);
    let addr2 = alloy_primitives::Address::repeat_byte(2);
    let b256_1 = alloy_primitives::B256::repeat_byte(1);
    let b256_2 = alloy_primitives::B256::repeat_byte(2);
    let u256_1 = alloy_primitives::U256::from(1u64);
    let u256_2 = alloy_primitives::U256::from(2u64);
    let h160_1 = primitive_types::H160::repeat_byte(1);
    let h160_2 = primitive_types::H160::repeat_byte(2);
    let h256_1 = primitive_types::H256::repeat_byte(1);
    let h256_2 = primitive_types::H256::repeat_byte(2);

    // Core high-yield nested BTree/HashMap/IndexMap combinations
    ex_nested_btrees(1u64, 2u64, 1u64, 2u64, 10u64, 20u64);
    ex_nested_btrees(1u64, 2u64, 1usize, 2usize, 10u64, 20u64);
    ex_nested_btrees(1u64, 2u64, String::from("a"), String::from("b"), 10u64, 20u64);
    ex_nested_btrees(1usize, 2usize, 1u64, 2u64, 10u64, 20u64);
    ex_nested_btrees(1usize, 2usize, 1usize, 2usize, 10u64, 20u64);
    ex_nested_btrees(1u32, 2u32, 1u64, 2u64, 10u64, 20u64);
    ex_nested_btrees(String::from("a"), String::from("b"), String::from("x"), String::from("y"), 10u64, 20u64);
    ex_nested_btrees(String::from("a"), String::from("b"), 1u64, 2u64, String::from("v1"), String::from("v2"));
    ex_nested_btrees(addr1, addr2, 1u64, 2u64, u256_1, u256_2);
    ex_nested_btrees(addr1, addr2, 1usize, 2usize, 10u64, 20u64);
    ex_nested_btrees(addr1, addr2, b256_1, b256_2, u256_1, u256_2);
    ex_nested_btrees(h160_1, h160_2, 1u64, 2u64, 10u64, 20u64);
    ex_nested_btrees(h160_1, h160_2, h256_1, h256_2, 10u64, 20u64);
    ex_nested_btrees([1u8; 20], [2u8; 20], 1u64, 2u64, 10u64, 20u64);
    ex_nested_btrees([1u8; 32], [2u8; 32], 1u64, 2u64, 10u64, 20u64);

    ex_nested_hashmaps::<u64, u64, u64, R>(1, 2, 3, 4, 10, 20);
    ex_nested_hashmaps::<u64, usize, u64, R>(1, 2, 3, 4, 10, 20);
    ex_nested_hashmaps::<usize, usize, u64, R>(1, 2, 3, 4, 10, 20);
    ex_nested_hashmaps::<String, String, u64, R>("a".into(), "b".into(), "x".into(), "y".into(), 10, 20);
    ex_nested_hashmaps::<String, String, serde_json::Value, R>("a".into(), "b".into(), "x".into(), "y".into(), serde_json::json!(1), serde_json::json!(2));
    ex_nested_hashmaps::<_, _, _, R>(addr1, addr2, 1u64, 2u64, u256_1, u256_2);
    ex_nested_hashmaps::<_, _, _, R>(addr1, addr2, b256_1, b256_2, u256_1, u256_2);
    ex_nested_hashmaps::<_, _, _, R>(h160_1, h160_2, 1u64, 2u64, 10u64, 20u64);
    ex_nested_hashmaps::<_, _, _, F>(addr1, addr2, b256_1, b256_2, u256_1, u256_2);
    ex_nested_hashmaps::<_, _, _, F>(1u64, 2u64, 3u64, 4u64, 10u64, 20u64);
    ex_nested_hashmaps::<_, _, _, F>(String::from("a"), String::from("b"), String::from("x"), String::from("y"), 10u64, 20u64);
    ex_nested_hashmaps::<_, _, _, A>(addr1, addr2, b256_1, b256_2, u256_1, u256_2);
    ex_nested_hashmaps::<_, _, _, X>(addr1, addr2, 1u64, 2u64, 10u64, 20u64);

    ex_nested_vecs(1u64, 2u64);
    ex_nested_vecs(1usize, 2usize);
    ex_nested_vecs(1u32, 2u32);
    ex_nested_vecs(String::from("a"), String::from("b"));
    ex_nested_vecs(vec![1u8], vec![2u8]);
    ex_nested_vecs(addr1, addr2);
    ex_nested_vecs(b256_1, b256_2);
    ex_nested_vecs(u256_1, u256_2);
    ex_nested_vecs(h160_1, h160_2);
    ex_nested_vecs(h256_1, h256_2);
    ex_nested_vecs(bytes::Bytes::from_static(b"a"), bytes::Bytes::from_static(b"b"));
    ex_nested_vecs(rust_decimal::Decimal::from(1i64), rust_decimal::Decimal::from(2i64));
    ex_nested_vecs(ordered_float::OrderedFloat(1.0f64), ordered_float::OrderedFloat(2.0f64));
}
