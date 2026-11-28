#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Pure-Rust (zero external dependencies) reconstruction of 3 first-party
//! Linux x86-64 node #115 `consensus` PIE FDEs (`882 B`):
//! - `ValidatorStakes::has_quorum` (`0x4d3e1a0..0x4d3e30d`, `365 B`)
//! - `ValidatorStakes::contains_key` (`0x4d3e310..0x4d3e3f2`, `226 B`)
//! - `ConsensusEvent::fmt` (`0x59d70b0..0x59d71d3`, `291 B`)
//!
//! Compiled live under `rustc +1.95.0 --edition=2021 --crate-type=rlib
//! -C opt-level=3 -C overflow-checks=yes -C relocation-model=pie -C lto=off --emit=obj`.

use core::fmt;
use std::collections::{btree_map, vec_deque, BTreeMap, BTreeSet, VecDeque};
use std::hint::black_box;

pub enum L1Map<K, V> {
    Small(VecDeque<(K, V)>),
    Large(BTreeMap<K, V>),
}

pub enum L1Iter<'a, K, V> {
    Small(vec_deque::Iter<'a, (K, V)>),
    Large(btree_map::Iter<'a, K, V>),
}

impl<'a, K, V> Iterator for L1Iter<'a, K, V> {
    type Item = (&'a K, &'a V);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Small(it) => it.next().map(|(k, v)| (k, v)),
            Self::Large(it) => it.next(),
        }
    }
}

#[inline(never)]
fn bsearch_small(v: &VecDeque<([u8; 20], u64)>, k: &[u8; 20]) -> Result<usize, usize> {
    v.binary_search_by(|(x, _)| x.cmp(k))
}

/// Matches node #115 `0x4d3e310..0x4d3e3f2` (`226 B`, `consensus`
/// `ValidatorStakes::contains_key` over `L1Map<[u8; 20], u64>`).
#[inline(never)]
pub fn validator_stakes_contains_key(m: &L1Map<[u8; 20], u64>, k: &[u8; 20]) -> bool {
    match m {
        L1Map::Small(v) => bsearch_small(v, k).is_ok(),
        L1Map::Large(b) => b.contains_key(k),
    }
}

#[inline(never)]
#[track_caller]
pub fn sat_sum<I: Iterator<Item = u64>>(iter: I) -> u64 {
    let loc = std::panic::Location::caller();
    black_box((iter, loc));
    black_box(0u64)
}

/// Matches node #115 `0x4d3e1a0..0x4d3e30d` (`365 B`, `consensus`
/// `ValidatorStakes::has_quorum`: 128-bit `3 * signed_stake > 2 * total_stake`).
#[inline(never)]
pub fn validator_stakes_has_quorum(
    stakes: &L1Map<[u8; 20], u64>,
    validators: &BTreeSet<[u8; 20]>,
) -> bool {
    let signed = sat_sum(validators.iter().map(|v| {
        let s = match stakes {
            L1Map::Small(d) => d.binary_search_by(|(k, _)| k.cmp(v)).map_or(0, |i| d[i].1),
            L1Map::Large(m) => m.get(v).copied().unwrap_or(0),
        };
        let vr: &&BTreeSet<[u8; 20]> = &validators;
        black_box(vr);
        s
    }));
    let total = sat_sum(
        match stakes {
            L1Map::Small(d) => L1Iter::Small(d.iter()),
            L1Map::Large(m) => L1Iter::Large(m.iter()),
        }
        .map(|(_, s)| *s),
    );
    u128::from(signed) * 3 > u128::from(total) * 2
}

#[derive(Debug)]
pub enum MsgKind {
    ExternalTx,
    Tx,
    Block,
    Vote,
    Timeout,
    Tc,
    Heartbeat,
    HeartbeatAck,
    RpcResponse,
    RpcFailed,
}

pub enum ConsensusEvent {
    InMsg(MsgKind),
    ExecutionState,
    TriggerTimeout,
    EmptyBlockTimer,
    PeriodicVoteStream,
    JailVoteTimer,
    L1Hash,
    AbciDigest,
    Artifact,
}

/// Matches node #115 `0x59d70b0..0x59d71d3` (`291 B`, `consensus`
/// `ConsensusEvent::fmt` with niche-packed `InMsg(MsgKind)` + 8 unit event arms).
impl fmt::Debug for ConsensusEvent {
    #[inline(never)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InMsg(m) => write!(f, "InMsg({m:?})"),
            Self::ExecutionState => write!(f, "ExecutionState"),
            Self::TriggerTimeout => write!(f, "TriggerTimeout"),
            Self::EmptyBlockTimer => write!(f, "EmptyBlockTimer"),
            Self::PeriodicVoteStream => write!(f, "PeriodicVoteStream"),
            Self::JailVoteTimer => write!(f, "JailVoteTimer"),
            Self::L1Hash => write!(f, "L1Hash"),
            Self::AbciDigest => write!(f, "AbciDigest"),
            Self::Artifact => write!(f, "Artifact"),
        }
    }
}
