//! Signer collector `0x4e00160`: every certificate key must be in the stake map; collects the key set.

use std::collections::BTreeSet;

use crate::sigmap::{Address, SigMap};
use crate::stake::StakeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Collected {
    /// Tag `0x2e` with the key set (sorted, repeated keys once; built natively by `0x53492e0`).
    Signers(BTreeSet<Address>),
    /// Tag `0x2c` with the first key, in visiting order, that is not in the stake map.
    UnknownSigner(Address),
}

pub fn collect_signers(set: &StakeSet, sigs: &SigMap) -> Collected {
    let mut signers = BTreeSet::new();
    for (key, _) in sigs.entries() {
        if !set.stakes.contains(key) {
            return Collected::UnknownSigner(*key);
        }
        signers.insert(*key);
    }
    Collected::Signers(signers)
}
