use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[inline(never)]
fn ex_vec_sort<T: Ord + Clone + Debug + Default + serde::Serialize + serde::de::DeserializeOwned>(arg: &str, seed: T) {
    let mut v: Vec<T> = vec![seed.clone(), T::default(), seed.clone()];
    v.sort();
    v.sort_unstable();
    v.dedup();
    let _ = core::hint::black_box(v.binary_search(&seed));
    let mut vd = VecDeque::from(v.clone());
    vd.push_front(seed.clone());
    vd.pop_back();
    let mut bh = BinaryHeap::from(v.clone());
    bh.push(seed.clone());
    let _ = core::hint::black_box(bh.pop());
    let mut bs = BTreeSet::new();
    bs.insert(seed.clone());
    let _ = core::hint::black_box((bs.contains(&seed), bs.range(..).count(), format!("{v:?} {bs:?}")));
    let _ = core::hint::black_box((
        serde_json::from_str::<T>(arg),
        serde_json::from_str::<Vec<T>>(arg),
        serde_json::from_str::<Option<T>>(arg),
        serde_json::from_str::<BTreeSet<T>>(arg),
        serde_json::to_string(&v),
        serde_json::to_vec(&v),
        rmp_serde::from_slice::<T>(arg.as_bytes()),
        rmp_serde::from_slice::<Vec<T>>(arg.as_bytes()),
        rmp_serde::from_slice::<Option<T>>(arg.as_bytes()),
        rmp_serde::from_slice::<BTreeSet<T>>(arg.as_bytes()),
        rmp_serde::to_vec(&v),
        rmp_serde::to_vec_named(&v),
        bincode1::deserialize::<Vec<T>>(arg.as_bytes()),
        bincode1::serialize(&v),
    ));
}

#[inline(never)]
fn ex_maps<K, V>(arg: &str, k: K, v: V)
where
    K: Ord + Eq + Hash + Clone + Debug + Default + serde::Serialize + serde::de::DeserializeOwned,
    V: Clone + Debug + Default + serde::Serialize + serde::de::DeserializeOwned,
{
    let mut hm = HashMap::<K, V>::new();
    hm.insert(k.clone(), v.clone());
    let _ = hm.entry(k.clone()).or_insert_with(V::default);
    let _ = core::hint::black_box(hm.get(&k));
    let _ = core::hint::black_box(hm.clone());
    let _ = core::hint::black_box(hm.remove(&k));
    let mut hs = HashSet::<K>::new();
    hs.insert(k.clone());
    let _ = core::hint::black_box(hs.contains(&k));
    let _ = core::hint::black_box(hs.clone());
    let _ = core::hint::black_box(hs.remove(&k));
    let mut bm = BTreeMap::<K, V>::new();
    bm.insert(k.clone(), v.clone());
    let _ = bm.entry(k.clone()).or_insert_with(V::default);
    let _ = core::hint::black_box(bm.get(&k));
    let _ = core::hint::black_box(bm.clone());
    let _ = core::hint::black_box(bm.remove(&k));
    let mut hb15 = hashbrown::HashMap::<K, V>::new();
    hb15.insert(k.clone(), v.clone());
    let _ = core::hint::black_box(hb15.get(&k));
    let _ = core::hint::black_box(hb15.clone());
    let _ = core::hint::black_box(hb15.remove(&k));
    let mut hb16 = hashbrown_16::HashMap::<K, V>::new();
    hb16.insert(k.clone(), v.clone());
    let _ = core::hint::black_box(hb16.get(&k));
    let _ = core::hint::black_box(hb16.clone());
    let _ = core::hint::black_box(hb16.remove(&k));
    let mut im = indexmap::IndexMap::<K, V>::new();
    im.insert(k.clone(), v.clone());
    let _ = core::hint::black_box(im.get(&k));
    let _ = core::hint::black_box(im.clone());
    let _ = core::hint::black_box(im.shift_remove(&k));
    let _ = core::hint::black_box(im.swap_remove(&k));
    let mut is = indexmap::IndexSet::<K>::new();
    is.insert(k.clone());
    let _ = core::hint::black_box(is.contains(&k));
    let _ = core::hint::black_box(is.clone());
    let _ = core::hint::black_box(is.swap_remove(&k));
    let _ = core::hint::black_box((
        serde_json::from_str::<HashMap<K, V>>(arg),
        serde_json::from_str::<BTreeMap<K, V>>(arg),
        serde_json::from_str::<indexmap::IndexMap<K, V>>(arg),
        serde_json::to_string(&hm),
        serde_json::to_string(&bm),
        rmp_serde::from_slice::<HashMap<K, V>>(arg.as_bytes()),
        rmp_serde::from_slice::<BTreeMap<K, V>>(arg.as_bytes()),
        rmp_serde::from_slice::<HashSet<K>>(arg.as_bytes()),
        rmp_serde::from_slice::<indexmap::IndexMap<K, V>>(arg.as_bytes()),
        rmp_serde::to_vec(&hm),
        rmp_serde::to_vec(&bm),
        rmp_serde::to_vec_named(&bm),
        bincode1::deserialize::<HashMap<K, V>>(arg.as_bytes()),
        bincode1::deserialize::<BTreeMap<K, V>>(arg.as_bytes()),
    ));
}

#[inline(never)]
fn touch_ark_bls_bn(arg: &str) {
    use ark_ec::{pairing::Pairing, AffineRepr, VariableBaseMSM};
    use ark_ff::Field;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let g1 = ark_bls12_381::G1Affine::generator();
    let g2 = ark_bls12_381::G2Affine::generator();
    let fr = ark_bls12_381::Fr::from(arg.len() as u64 + 3);
    let p1 = ark_bls12_381::G1Projective::msm(&[g1, g1], &[fr, fr]);
    let p2 = ark_bls12_381::G2Projective::msm(&[g2, g2], &[fr, fr]);
    let ml = ark_bls12_381::Bls12_381::multi_pairing([g1], [g2]);
    let mut buf = Vec::new();
    let _ = g1.serialize_compressed(&mut buf);
    let _ = core::hint::black_box(ark_bls12_381::G1Affine::deserialize_compressed(&buf[..]));
    let _ = g2.serialize_compressed(&mut buf);
    let _ = core::hint::black_box(ark_bls12_381::G2Affine::deserialize_compressed(&buf[..]));
    let _ = core::hint::black_box((p1, p2, ml, fr.inverse()));

    let bg1 = ark_bn254::G1Affine::generator();
    let bg2 = ark_bn254::G2Affine::generator();
    let bfr = ark_bn254::Fr::from(arg.len() as u64 + 5);
    let _ = core::hint::black_box((
        ark_bn254::G1Projective::msm(&[bg1, bg1], &[bfr, bfr]),
        ark_bn254::G2Projective::msm(&[bg2, bg2], &[bfr, bfr]),
        ark_bn254::Bn254::multi_pairing([bg1], [bg2]),
        bfr.inverse(),
    ));
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    if arg == "run" {
        ex_vec_sort(&arg, 1u8);
        ex_vec_sort(&arg, 1u16);
        ex_vec_sort(&arg, 1u32);
        ex_vec_sort(&arg, 1u64);
        ex_vec_sort(&arg, 1u128);
        ex_vec_sort(&arg, 1usize);
        ex_vec_sort(&arg, 1i64);
        ex_vec_sort(&arg, true);
        ex_vec_sort(&arg, arg.clone());
        ex_vec_sort(&arg, vec![1u8, 2]);
        ex_vec_sort(&arg, [0u8; 20]);
        ex_vec_sort(&arg, [0u8; 32]);
        ex_vec_sort(&arg, (1u64, 2u64));
        ex_vec_sort(&arg, (1usize, 2u64));
        ex_vec_sort(&arg, (arg.clone(), 1u64));
        ex_vec_sort(&arg, ([0u8; 20], 1u64));
        ex_vec_sort(&arg, ([0u8; 32], 1u64));
        ex_vec_sort(&arg, primitive_types::H160::zero());
        ex_vec_sort(&arg, primitive_types::H256::zero());
        ex_vec_sort(&arg, primitive_types::U256::zero());
        ex_vec_sort(&arg, alloy_primitives::Address::ZERO);
        ex_vec_sort(&arg, alloy_primitives::B256::ZERO);
        ex_vec_sort(&arg, alloy_primitives::U256::ZERO);
        ex_vec_sort(&arg, rust_decimal::Decimal::ZERO);
        ex_vec_sort(&arg, ordered_float::OrderedFloat(1.0f64));
        ex_vec_sort(&arg, PathBuf::from(&arg));

        ex_maps(&arg, arg.clone(), 1u64);
        ex_maps(&arg, arg.clone(), arg.clone());
        ex_maps(&arg, arg.clone(), 1.0f64);
        ex_maps(&arg, arg.clone(), vec![1u64]);
        ex_maps(&arg, 1u64, 1u64);
        ex_maps(&arg, 1u64, arg.clone());
        ex_maps(&arg, 1u64, 1.0f64);
        ex_maps(&arg, 1u64, vec![1u8]);
        ex_maps(&arg, 1usize, 1u64);
        ex_maps(&arg, 1usize, 1.0f64);
        ex_maps(&arg, 1u32, 1u64);
        ex_maps(&arg, [0u8; 20], 1u64);
        ex_maps(&arg, [0u8; 20], [0u8; 32]);
        ex_maps(&arg, [0u8; 32], 1u64);
        ex_maps(&arg, primitive_types::H160::zero(), 1u64);
        ex_maps(&arg, primitive_types::H256::zero(), 1u64);
        ex_maps(&arg, alloy_primitives::Address::ZERO, alloy_primitives::U256::ZERO);
        ex_maps(&arg, alloy_primitives::B256::ZERO, alloy_primitives::U256::ZERO);
        let sa: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let _ = core::hint::black_box((
            serde_json::from_str::<HashMap<IpAddr, u64>>(&arg),
            serde_json::from_str::<HashMap<SocketAddr, u64>>(&arg),
            rmp_serde::from_slice::<HashMap<IpAddr, u64>>(arg.as_bytes()),
            rmp_serde::from_slice::<Vec<SocketAddr>>(arg.as_bytes()),
            sa, ip,
        ));
        touch_ark_bls_bn(&arg);
    }
}
