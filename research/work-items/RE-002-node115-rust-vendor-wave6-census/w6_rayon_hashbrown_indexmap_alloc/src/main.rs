use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{BuildHasher, Hash};
use std::hint::black_box;
use std::sync::Arc;
use rayon::prelude::*;

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[inline(never)]
fn ex_rayon_slice<T: Ord + Clone + Send + Sync>(items: Vec<T>) {
    let mut v1 = items.clone();
    v1.par_sort();
    v1.par_sort_unstable();
    v1.par_sort_by(|a, b| b.cmp(a));
    let _ = black_box(v1.par_iter().enumerate().map(|(i, x)| (i, x.clone())).collect::<Vec<_>>());
    let _ = black_box(v1.par_chunks(4).map(|c| c.len()).collect::<Vec<_>>());
    let _ = black_box(v1.par_chunks_exact(4).map(|c| c.len()).collect::<Vec<_>>());
    let _ = black_box(v1.par_windows(2).map(|w| w.len()).collect::<Vec<_>>());
    let _ = black_box(v1.par_rchunks(4).map(|c| c.len()).collect::<Vec<_>>());
    let _ = black_box(v1.par_iter().find_first(|x| black_box(**x == v1[0])));
    let _ = black_box(v1.par_iter().find_last(|x| black_box(**x == v1[0])));
    let _ = black_box(v1.par_iter().find_any(|x| black_box(**x == v1[0])));
    let _ = black_box(v1.par_iter().position_first(|x| black_box(*x == v1[0])));
    let _ = black_box(v1.par_iter().position_any(|x| black_box(*x == v1[0])));
    let _ = black_box(v1.par_iter().any(|x| black_box(*x == v1[0])));
    let _ = black_box(v1.par_iter().all(|x| black_box(*x >= v1[0])));
    let mut out = Vec::new();
    v1.clone().into_par_iter().collect_into_vec(&mut out);
    let _ = black_box(out);
    let _ = black_box(v1.into_par_iter().filter_map(|x| if black_box(true) { Some(x) } else { None }).collect::<Vec<_>>());
}

#[inline(never)]
fn ex_im_hb_rich<K: Eq + Hash + Ord + Clone, V: Clone + Default, S: BuildHasher + Default + Clone>(k1: K, k2: K, v1: V, v2: V) {
    // IndexMap rich ops (shift_insert, splice, retain, split_off, entry, swap_remove_full, shift_remove_full)
    let mut im: indexmap::IndexMap<K, V, S> = indexmap::IndexMap::with_capacity_and_hasher(8, S::default());
    let _ = im.insert_full(black_box(k1.clone()), black_box(v1.clone()));
    let _ = im.shift_insert(0, black_box(k2.clone()), black_box(v2.clone()));
    let _ = black_box(im.get_index(0));
    let _ = black_box(im.get_full(&k1));
    im.entry(k1.clone()).and_modify(|v| *v = v2.clone()).or_insert_with(V::default);
    im.retain(|k, _| black_box(k == &k1 || k == &k2));
    let tail = im.split_off(im.len() / 2);
    let _ = black_box(tail);
    let _ = black_box(im.swap_remove_full(&k1));
    let _ = black_box(im.shift_remove_full(&k2));
    im.shrink_to_fit();
    let _ = black_box(im.drain(..).collect::<Vec<_>>());

    // IndexSet
    let mut is: indexmap::IndexSet<K, S> = indexmap::IndexSet::with_capacity_and_hasher(8, S::default());
    is.insert(k1.clone());
    is.insert(k2.clone());
    let _ = black_box(is.shift_remove(&k1));
    let _ = black_box(is.swap_remove(&k2));

    // hashbrown 0.15.2 HashMap + HashSet + raw_entry_mut
    let mut hm: hashbrown::HashMap<K, V, S> = hashbrown::HashMap::with_capacity_and_hasher(8, S::default());
    hm.insert(k1.clone(), v1.clone());
    hm.insert(k2.clone(), v2.clone());
    let _ = black_box(hm.raw_entry_mut().from_key(&k1).or_insert(k1.clone(), v2.clone()));
    let _ = black_box(hm.remove_entry(&k2));
    hm.shrink_to_fit();
    let _ = black_box(hm.into_iter().collect::<Vec<_>>());

    let mut hs: hashbrown::HashSet<K, S> = hashbrown::HashSet::with_capacity_and_hasher(8, S::default());
    hs.insert(k1.clone());
    hs.insert(k2.clone());
    let _ = black_box(hs.take(&k1));

    // hashbrown 0.16.1 HashMap
    let mut hm16: hashbrown_16::HashMap<K, V, S> = hashbrown_16::HashMap::with_capacity_and_hasher(8, S::default());
    hm16.insert(k1.clone(), v1.clone());
    hm16.insert(k2.clone(), v2.clone());
    hm16.entry(k1.clone()).or_insert(v2.clone());
    let _ = black_box(hm16.remove(&k1));

    // std BTreeMap + HashMap with extra V types!
    let mut bm: BTreeMap<K, V> = BTreeMap::new();
    bm.insert(k1.clone(), v1.clone());
    bm.insert(k2.clone(), v2.clone());
    let _ = black_box(bm.remove(&k1));
    let mut sm: HashMap<K, V, S> = HashMap::with_hasher(S::default());
    sm.insert(k1, v1);
    sm.insert(k2, v2);
    let _ = black_box(sm.into_iter().collect::<Vec<_>>());
}

#[inline(never)]
fn ex_smallvec_extra<T: Ord + Clone>(a: T, b: T) {
    let mut s1: smallvec::SmallVec<[T; 1]> = smallvec::SmallVec::new();
    s1.push(a.clone()); s1.push(b.clone()); s1.sort(); let _ = black_box(s1);
    let mut s2: smallvec::SmallVec<[T; 2]> = smallvec::SmallVec::new();
    s2.push(a.clone()); s2.push(b.clone()); s2.push(a.clone()); s2.sort_unstable(); let _ = black_box(s2);
    let mut s8: smallvec::SmallVec<[T; 8]> = smallvec::SmallVec::new();
    for _ in 0..10 { s8.push(a.clone()); s8.push(b.clone()); }
    s8.sort(); s8.dedup(); let _ = black_box(s8);
    let mut s16: smallvec::SmallVec<[T; 16]> = smallvec::SmallVec::new();
    for _ in 0..18 { s16.push(a.clone()); }
    let _ = black_box(s16);
}

fn main() {
    type R = std::collections::hash_map::RandomState;
    type F = foldhash::fast::RandomState;
    type Q = foldhash::quality::RandomState;
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
    let dec1 = rust_decimal::Decimal::from(1i64);
    let dec2 = rust_decimal::Decimal::from(2i64);
    let of1 = ordered_float::OrderedFloat(1.0f64);
    let of2 = ordered_float::OrderedFloat(2.0f64);

    // Rayon deep parallel slice / iterator monomorphizations
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build().unwrap();
    pool.install(|| {
        ex_rayon_slice((0u8..32).rev().collect());
        ex_rayon_slice((0u32..32).rev().collect());
        ex_rayon_slice((0u64..32).rev().collect());
        ex_rayon_slice((0usize..32).rev().collect());
        ex_rayon_slice((-16i64..16).rev().collect());
        ex_rayon_slice((0..16).map(|i| format!("s{i}")).collect());
        ex_rayon_slice((0u8..16).map(|i| vec![i; 4]).collect());
        ex_rayon_slice((0u8..16).map(|i| [i; 20]).collect());
        ex_rayon_slice((0u8..16).map(|i| [i; 32]).collect());
        ex_rayon_slice((0u64..16).map(|i| (16 - i, i)).collect());
        ex_rayon_slice((0usize..16).map(|i| (16 - i, i as u64)).collect());
        ex_rayon_slice((0u8..16).map(alloy_primitives::Address::repeat_byte).collect());
        ex_rayon_slice((0u8..16).map(alloy_primitives::B256::repeat_byte).collect());
        ex_rayon_slice((0u64..16).map(alloy_primitives::U256::from).collect());
        let _: BTreeMap<u64, u64> = (0u64..32).into_par_iter().map(|i| (i, i * 2)).collect();
        let _: HashMap<u64, u64> = (0u64..32).into_par_iter().map(|i| (i, i * 2)).collect();
        let _: BTreeSet<u64> = (0u64..32).into_par_iter().collect();
        let _: HashSet<u64> = (0u64..32).into_par_iter().collect();
    });

    // High-yield IndexMap 2.7.1 + hashbrown 0.15.2/0.16.1 + BTreeMap + HashMap with rich value types!
    ex_im_hb_rich::<String, serde_json::Value, R>("a".into(), "b".into(), serde_json::json!(1), serde_json::json!("x"));
    ex_im_hb_rich::<String, bool, R>("a".into(), "b".into(), true, false);
    ex_im_hb_rich::<String, f64, R>("a".into(), "b".into(), 1.0, 2.0);
    ex_im_hb_rich::<String, Vec<u8>, R>("a".into(), "b".into(), vec![1], vec![2]);
    ex_im_hb_rich::<String, Vec<String>, R>("a".into(), "b".into(), vec!["x".into()], vec!["y".into()]);
    ex_im_hb_rich::<String, Option<u64>, R>("a".into(), "b".into(), Some(1), None);
    ex_im_hb_rich::<String, usize, F>("a".into(), "b".into(), 1, 2);
    ex_im_hb_rich::<String, u64, Q>("a".into(), "b".into(), 1, 2);
    ex_im_hb_rich::<String, u64, A>("a".into(), "b".into(), 1, 2);
    ex_im_hb_rich::<String, u64, X>("a".into(), "b".into(), 1, 2);
    ex_im_hb_rich::<u64, f64, R>(1, 2, 1.0, 2.0);
    ex_im_hb_rich::<u64, i64, R>(1, 2, -1, 2);
    ex_im_hb_rich::<u64, bool, R>(1, 2, true, false);
    ex_im_hb_rich::<u64, Vec<u64>, R>(1, 2, vec![1], vec![2]);
    ex_im_hb_rich::<u64, Option<u64>, R>(1, 2, Some(1), None);
    ex_im_hb_rich::<u64, (u64, u64), R>(1, 2, (1, 2), (3, 4));
    ex_im_hb_rich::<u64, u64, Q>(1, 2, 10, 20);
    ex_im_hb_rich::<usize, bool, R>(1, 2, true, false);
    ex_im_hb_rich::<usize, f64, R>(1, 2, 1.0, 2.0);
    ex_im_hb_rich::<usize, Vec<u8>, R>(1, 2, vec![1], vec![2]);
    ex_im_hb_rich::<u32, u32, R>(1, 2, 3, 4);
    ex_im_hb_rich::<u32, String, R>(1, 2, "a".into(), "b".into());
    ex_im_hb_rich::<_, alloy_primitives::U256, R>(addr1, addr2, u256_1, u256_2);
    ex_im_hb_rich::<_, alloy_primitives::U256, F>(addr1, addr2, u256_1, u256_2);
    ex_im_hb_rich::<_, alloy_primitives::U256, A>(addr1, addr2, u256_1, u256_2);
    ex_im_hb_rich::<_, alloy_primitives::U256, X>(addr1, addr2, u256_1, u256_2);
    ex_im_hb_rich::<_, alloy_primitives::B256, F>(addr1, addr2, b256_1, b256_2);
    ex_im_hb_rich::<_, alloy_primitives::U256, F>(b256_1, b256_2, u256_1, u256_2);
    ex_im_hb_rich::<_, u64, F>(h160_1, h160_2, 1, 2);
    ex_im_hb_rich::<_, rust_decimal::Decimal, R>(1u64, 2u64, dec1, dec2);
    ex_im_hb_rich::<_, ordered_float::OrderedFloat<f64>, R>(1u64, 2u64, of1, of2);
    ex_im_hb_rich::<_, bytes::Bytes, R>(b256_1, b256_2, bytes::Bytes::from_static(b"a"), bytes::Bytes::from_static(b"b"));
    ex_im_hb_rich::<Arc<str>, u64, R>(Arc::from("a"), Arc::from("b"), 1, 2);

    // SmallVec extra widths
    ex_smallvec_extra(1u8, 2u8);
    ex_smallvec_extra(1u32, 2u32);
    ex_smallvec_extra(1u64, 2u64);
    ex_smallvec_extra(1usize, 2usize);
    ex_smallvec_extra(String::from("a"), String::from("b"));
    ex_smallvec_extra(addr1, addr2);
    ex_smallvec_extra(b256_1, b256_2);
}
