//! Selected read-only digest-candidate admission over valid logical snapshots.
//! Membership eligibility is supplied from the caller's separate check.
use std::collections::{BTreeMap, BTreeSet};

pub type Digest = [u8; 32];
pub type Key32 = [u8; 32];
pub type Key20 = [u8; 20];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Candidate {
    pub keys32: BTreeSet<Key32>,
    pub keys20: BTreeSet<Key20>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeightEntry {
    pub selected: Option<Digest>,
    pub candidates: BTreeMap<Digest, Candidate>,
}

pub type Snapshot = BTreeMap<u64, HeightEntry>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Voter {
    Key32(Key32),
    Key20(Key20),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    NotEligible,
    ConflictingSelection,
    ExistingCandidate,
    AdmitNew { count: u64 },
    AtCapacity { count: u64 },
}

/// Query one key family, after the caller's separately established eligibility
/// test. This does not insert a vote, validate signatures or select a digest.
/// A second call after any insertion must receive the updated snapshot.
pub fn admission_for(
    snapshot: &Snapshot,
    height: u64,
    digest: Digest,
    voter: Voter,
    eligible: bool,
) -> Admission {
    if !eligible {
        return Admission::NotEligible;
    }
    if let Some(entry) = snapshot.get(&height) {
        if entry.selected.is_some_and(|selected| selected != digest) {
            return Admission::ConflictingSelection;
        }
        if entry.candidates.contains_key(&digest) {
            return Admission::ExistingCandidate;
        }
    }
    let mut count = 0_u64;
    for entry in snapshot.values() {
        for (candidate_digest, candidate) in &entry.candidates {
            if entry.selected.as_ref() == Some(candidate_digest) {
                continue;
            }
            let present = match voter {
                Voter::Key32(key) => candidate.keys32.contains(&key),
                Voter::Key20(key) => candidate.keys20.contains(&key),
            };
            count = count.saturating_add(u64::from(present));
        }
    }
    if count < 2200 {
        Admission::AdmitNew { count }
    } else {
        Admission::AtCapacity { count }
    }
}
