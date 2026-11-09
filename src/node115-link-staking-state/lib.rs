//! Selected successful-state and rejection behavior of node115 link staking.
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
use alloc::collections::{BTreeMap, BTreeSet};

pub type Key = [u8; 20];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Link {
    pub tag: u8,
    pub peer: Key,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    pub staked: BTreeSet<Key>,
    pub links: BTreeMap<Key, Link>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    NoStakedKey,
    SameKey,
    TradingAlreadyLinked,
    StakingAlreadyLinked,
    PendingRequestRequired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Accepted,
    Rejected(Error),
}

/// Apply the selected wrapper's two modes to valid logical state.
/// Raw mode zero requests; every nonzero byte selects finalization.
/// Allocation, error construction, external authorization and unwind are excluded.
pub fn apply(state: &mut State, payload: Key, caller: Key, mode: u8) -> Outcome {
    if mode == 0 {
        let (a, b) = (payload, caller);
        if !state.staked.contains(&a) {
            return Outcome::Rejected(Error::NoStakedKey);
        }
        if a == b {
            return Outcome::Rejected(Error::SameKey);
        }
        if state.links.get(&b).is_some_and(|v| v.tag != 0) {
            return Outcome::Rejected(Error::TradingAlreadyLinked);
        }
        if state.links.get(&a).is_some_and(|v| v.tag != 0) {
            return Outcome::Rejected(Error::StakingAlreadyLinked);
        }
        state.links.insert(b, Link { tag: 0, peer: a });
    } else {
        let (a, b) = (caller, payload);
        if !state
            .links
            .get(&b)
            .is_some_and(|v| v.tag == 0 && v.peer == a)
        {
            return Outcome::Rejected(Error::PendingRequestRequired);
        }
        if state.links.get(&a).is_some_and(|v| v.tag != 0) {
            return Outcome::Rejected(Error::StakingAlreadyLinked);
        }
        state.links.insert(b, Link { tag: 1, peer: a });
        state.links.insert(a, Link { tag: 2, peer: b });
    }
    Outcome::Accepted
}
