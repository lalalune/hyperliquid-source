#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Pure-Rust reconstruction of node #115 `base/src/l1_map/entry.rs`
//! (`Entry`, `VacantEntry`, `OccupiedEntry`) reproducing 79 strictly disjoint
//! first-party business-logic FDEs (`19,901 B`) under `rustc 1.95.0`.

use std::collections::{btree_map, BTreeMap, VecDeque};

pub enum Entry<'a, K, V> {
    Vacant(VacantEntry<'a, K, V>),
    Occupied(OccupiedEntry<'a, K, V>),
}

pub enum VacantEntry<'a, K, V> {
    Small {
        map: &'a mut VecDeque<(K, V)>,
        idx: usize,
        key: K,
    },
    Large(btree_map::VacantEntry<'a, K, V>),
}

pub enum OccupiedEntry<'a, K, V> {
    Small {
        map: &'a mut VecDeque<(K, V)>,
        idx: usize,
    },
    Large(btree_map::OccupiedEntry<'a, K, V>),
}

impl<'a, K: Ord, V> OccupiedEntry<'a, K, V> {
    #[inline(never)]
    pub fn get(&self) -> &V {
        match self {
            Self::Small { map, idx } => &map.get(*idx).expect("Out of bounds access").1,
            Self::Large(entry) => entry.get(),
        }
    }

    #[inline(never)]
    pub fn get_mut(&mut self) -> &mut V {
        match self {
            Self::Small { map, idx } => &mut map.get_mut(*idx).expect("Out of bounds access").1,
            Self::Large(entry) => entry.get_mut(),
        }
    }

    #[inline(always)]
    pub fn into_mut(self) -> &'a mut V {
        match self {
            Self::Small { map, idx } => &mut map.get_mut(idx).expect("Out of bounds access").1,
            Self::Large(entry) => entry.into_mut(),
        }
    }

    #[inline(never)]
    pub fn remove_entry(self) -> (K, V) {
        match self {
            Self::Small { map, idx } => map.remove(idx).expect("occupied entry index"),
            Self::Large(entry) => entry.remove_entry(),
        }
    }
}

impl<'a, K: Ord, V> VacantEntry<'a, K, V> {
    #[inline(always)]
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
    #[inline(never)]
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Self::Occupied(entry) => entry.into_mut(),
            Self::Vacant(entry) => entry.insert_entry(default).into_mut(),
        }
    }

    #[inline(never)]
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

// Minimal layout-equivalent key/value carrier types for the 24 instantiated (K, V) pairs.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K4(u32);
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K8(u64);
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K12([u32; 3]);
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K16([u64; 2]);
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K20([u8; 20]);
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K32([u64; 4]);
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy)]
pub struct K176([u64; 22]);

#[derive(Default)]
pub struct V8(u64);
#[derive(Default)]
pub struct V12([u32; 3]);
#[derive(Default)]
pub struct V24([u64; 3]);
#[derive(Default)]
pub struct V32([u64; 4]);
#[derive(Default)]
pub struct V48([u64; 6]);
#[derive(Default)]
pub struct V88([u64; 11]);
#[derive(Default)]
pub struct V112([u64; 14]);
#[derive(Default)]
pub struct V128([u64; 16]);
#[derive(Default)]
pub struct V160([u64; 20]);
#[derive(Default)]
pub struct VVec(Vec<u64>);
#[derive(Default)]
pub struct VDeque(VecDeque<u64>);
#[derive(Default)]
pub struct VMap(BTreeMap<u64, u64>);

pub enum L1MapInner {
    Small(VecDeque<(u64, u64)>),
    Large(BTreeMap<u64, u64>),
}

pub struct VL1Map(L1MapInner);

impl Default for VL1Map {
    fn default() -> Self {
        Self(L1MapInner::Small(VecDeque::new()))
    }
}

macro_rules! inst {
    ($fn_name:ident, $k:ty, $v:ty) => {
        pub fn $fn_name<'a>(
            e1: Entry<'a, $k, $v>,
            e2: Entry<'a, $k, $v>,
            d: $v,
            o1: &'a OccupiedEntry<'a, $k, $v>,
            o2: &'a mut OccupiedEntry<'a, $k, $v>,
            o3: OccupiedEntry<'a, $k, $v>,
            bo: btree_map::OccupiedEntry<'a, $k, $v>,
        ) -> (&'a mut $v, &'a mut $v, &'a $v, &'a mut $v, ($k, $v), ($k, $v)) {
            (
                e1.or_default(),
                e2.or_insert(d),
                o1.get(),
                o2.get_mut(),
                o3.remove_entry(),
                bo.remove_entry(),
            )
        }
    };
}

inst!(i_k4_v8, K4, V8);
inst!(i_k4_vvec, K4, VVec);
inst!(i_k8_v8, K8, V8);
inst!(i_k8_v12, K8, V12);
inst!(i_k8_v24, K8, V24);
inst!(i_k8_v32, K8, V32);
inst!(i_k8_v48, K8, V48);
inst!(i_k8_v112, K8, V112);
inst!(i_k8_v160, K8, V160);
inst!(i_k8_vvec, K8, VVec);
inst!(i_k8_vdeque, K8, VDeque);
inst!(i_k8_vmap, K8, VMap);
inst!(i_k12_vvec, K12, VVec);
inst!(i_k16_v8, K16, V8);
inst!(i_k20_v8, K20, V8);
inst!(i_k20_v12, K20, V12);
inst!(i_k20_v32, K20, V32);
inst!(i_k20_vvec, K20, VVec);
inst!(i_k20_vdeque, K20, VDeque);
inst!(i_k20_vmap, K20, VMap);
inst!(i_k20_vl1map, K20, VL1Map);
inst!(i_k32_v32, K32, V32);
inst!(i_k32_v88, K32, V88);
inst!(i_k176_v128, K176, V128);
