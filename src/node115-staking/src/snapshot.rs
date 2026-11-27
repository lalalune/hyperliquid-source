//! Independently authored Rust reconstruction of node #115 epoch validator
//! snapshot lookup (`0x36c8430`), epoch stake quorum (`0x36c7f70`, `staking.rs:185`),
//! unique profile extraction (`0x36c7b30`, `staking.rs:239/243`), and
//! bidirectional snapshot member queries (`0x36ca5b0` / `0x36ca700`).

use std::collections::BTreeMap;

use crate::epoch_ring::{Search, search as ring_search};
use crate::weight_comparison::exceeds_threshold;

pub type Address = [u8; 20];
pub type ValidatorKey = [u8; 32];

/// Exact status discriminants dropped/returned by `0x36c8430`, `0x36c7f70`, and `0x36c7b30`.
pub const STATUS_MISSING_EPOCH: u16 = 0x9b;
pub const STATUS_NOT_VALIDATOR: u16 = 0x2b;

/// Errors returned by epoch snapshot queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    /// Status `0x9b`: no snapshot recorded for the exact requested epoch.
    MissingEpoch(u64),
    /// Status `0x2b`: epoch snapshot exists, but signer is not a member.
    NotValidator,
    /// `staking.rs:243` assertion: duplicate validator profile in snapshot.
    DuplicateProfile(ValidatorKey),
}

impl SnapshotError {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            SnapshotError::MissingEpoch(_) => Some(STATUS_MISSING_EPOCH),
            SnapshotError::NotValidator => Some(STATUS_NOT_VALIDATOR),
            SnapshotError::DuplicateProfile(_) => None,
        }
    }
}

/// One validator row stored inside an epoch snapshot (`0x68`-byte ring element
/// or `0x48`-byte B-tree value).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatorEntry {
    pub key: ValidatorKey,
    pub signer: Address,
    pub hot_address: Address,
    pub stake: u64,
}

/// Validators active for a single epoch.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EpochSnapshot {
    pub epoch: u64,
    pub entries: Vec<ValidatorEntry>,
}

impl EpochSnapshot {
    /// Full-scan 20-byte signer membership check matching `0x36c8430`.
    pub fn contains_signer(&self, signer: &Address) -> bool {
        let mut found = false;
        for entry in &self.entries {
            found |= entry.signer == *signer;
        }
        found
    }

    /// Reconstructs `0x36ca5b0` (`staking-snapshot-members-115`): signer address -> validator key.
    pub fn key_for_signer(&self, signer: &Address) -> Option<ValidatorKey> {
        self.entries
            .iter()
            .find(|e| e.signer == *signer)
            .map(|e| e.key)
    }

    /// Reconstructs `0x36ca700` (`staking-snapshot-members-115`): validator key -> signer address.
    pub fn signer_for_key(&self, key: &ValidatorKey) -> Option<Address> {
        self.entries
            .iter()
            .find(|e| e.key == *key)
            .map(|e| e.signer)
    }
}

/// Epoch-indexed validator snapshot store matching `0x36c8430`, `0x36c7f70`, and `0x36c7b30`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotStore {
    /// Active epoch word (`[store+0x58]`).
    pub active_epoch: u64,
    /// Snapshots kept sorted ascending by `epoch`.
    snapshots: Vec<EpochSnapshot>,
}

impl SnapshotStore {
    pub fn new(active_epoch: u64) -> Self {
        Self {
            active_epoch,
            snapshots: Vec::new(),
        }
    }

    pub fn insert_snapshot(&mut self, snapshot: EpochSnapshot) {
        match self
            .snapshots
            .binary_search_by_key(&snapshot.epoch, |s| s.epoch)
        {
            Ok(idx) => self.snapshots[idx] = snapshot,
            Err(idx) => self.snapshots.insert(idx, snapshot),
        }
    }

    /// Exact-epoch lookup using `node115_validator_epoch_ring::search` (no nearest-lower rule,
    /// no 32-bit truncation, matching `0x4551810` / `0x36c8430`).
    pub fn snapshot_for_epoch(&self, epoch: u64) -> Result<&EpochSnapshot, SnapshotError> {
        let epochs: Vec<u64> = self.snapshots.iter().map(|s| s.epoch).collect();
        match ring_search(&epochs, 0, epochs.len(), epoch) {
            Ok(Search::Found { logical_index }) => Ok(&self.snapshots[logical_index]),
            _ => Err(SnapshotError::MissingEpoch(epoch)),
        }
    }

    /// Reconstructs `0x36c8430`: checks whether `signer` is in `active_epoch`'s snapshot.
    pub fn is_active_validator(&self, signer: &Address) -> Result<(), SnapshotError> {
        let snap = self.snapshot_for_epoch(self.active_epoch)?;
        if snap.contains_signer(signer) {
            Ok(())
        } else {
            Err(SnapshotError::NotValidator)
        }
    }

    /// Reconstructs `0x36c7f70` (`l1/src/staking.rs:185`): looks up `active_epoch`,
    /// projects `(key, stake)` weights, and delegates to `0x422e0f0`
    /// (`node115_staking_weight_comparison::exceeds_threshold`).
    pub fn active_epoch_has_quorum(
        &self,
        selected_keys: impl IntoIterator<Item = ValidatorKey>,
    ) -> Result<bool, SnapshotError> {
        let snap = self.snapshot_for_epoch(self.active_epoch)?;
        let weights: BTreeMap<ValidatorKey, u64> = snap
            .entries
            .iter()
            .map(|e| (e.key, e.stake))
            .collect();
        Ok(exceeds_threshold(&weights, selected_keys))
    }

    /// Reconstructs `0x36c7b30` (`l1/src/staking.rs:239,243`): builds a unique
    /// validator-key -> entry map for `epoch`, failing if `epoch` is absent
    /// (`0x9b`) or if any validator key duplicates (`profiles.insert` assertion).
    pub fn epoch_profiles(
        &self,
        epoch: u64,
    ) -> Result<BTreeMap<ValidatorKey, ValidatorEntry>, SnapshotError> {
        let snap = self.snapshot_for_epoch(epoch)?;
        let mut profiles = BTreeMap::new();
        for &entry in &snap.entries {
            if profiles.insert(entry.key, entry).is_some() {
                return Err(SnapshotError::DuplicateProfile(entry.key));
            }
        }
        Ok(profiles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> ValidatorKey {
        let mut k = [0u8; 32];
        k[31] = b;
        k
    }

    fn addr(b: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = b;
        a
    }

    #[test]
    fn exact_epoch_matching_rejects_nearest_lower_and_32bit_alias() {
        let mut store = SnapshotStore::new(10);
        store.insert_snapshot(EpochSnapshot {
            epoch: 10,
            entries: vec![
                ValidatorEntry {
                    key: key(1),
                    signer: addr(1),
                    hot_address: addr(11),
                    stake: 70,
                },
                ValidatorEntry {
                    key: key(2),
                    signer: addr(2),
                    hot_address: addr(12),
                    stake: 30,
                },
            ],
        });

        assert_eq!(store.is_active_validator(&addr(1)), Ok(()));
        assert_eq!(
            store.is_active_validator(&addr(9)),
            Err(SnapshotError::NotValidator)
        );
        assert_eq!(SnapshotError::NotValidator.status_code(), Some(0x2b));

        // Epoch 11 does NOT fall back to epoch 10; epoch 10 + 2^32 does NOT truncate.
        assert_eq!(
            store.snapshot_for_epoch(11),
            Err(SnapshotError::MissingEpoch(11))
        );
        assert_eq!(
            store.snapshot_for_epoch(10 + (1u64 << 32)),
            Err(SnapshotError::MissingEpoch(10 + (1u64 << 32)))
        );
        assert_eq!(SnapshotError::MissingEpoch(11).status_code(), Some(0x9b));
    }

    #[test]
    fn quorum_and_profile_extraction_match_staking_rs_semantics() {
        let mut store = SnapshotStore::new(5);
        store.insert_snapshot(EpochSnapshot {
            epoch: 5,
            entries: vec![
                ValidatorEntry {
                    key: key(1),
                    signer: addr(1),
                    hot_address: addr(1),
                    stake: 200,
                },
                ValidatorEntry {
                    key: key(2),
                    signer: addr(2),
                    hot_address: addr(2),
                    stake: 100,
                },
            ],
        });

        // 200/300 is exact 2/3 -> strict > fails; 300/300 passes.
        assert_eq!(store.active_epoch_has_quorum([key(1)]), Ok(false));
        assert_eq!(store.active_epoch_has_quorum([key(1), key(2)]), Ok(true));

        let profiles = store.epoch_profiles(5).unwrap();
        assert_eq!(profiles.len(), 2);
        let snap = store.snapshot_for_epoch(5).unwrap();
        assert_eq!(snap.key_for_signer(&addr(2)), Some(key(2)));
        assert_eq!(snap.signer_for_key(&key(1)), Some(addr(1)));

        // Duplicate validator profile triggers DuplicateProfile (`staking.rs:243` assertion).
        store.insert_snapshot(EpochSnapshot {
            epoch: 6,
            entries: vec![
                ValidatorEntry {
                    key: key(1),
                    signer: addr(1),
                    hot_address: addr(1),
                    stake: 10,
                },
                ValidatorEntry {
                    key: key(1),
                    signer: addr(2),
                    hot_address: addr(2),
                    stake: 20,
                },
            ],
        });
        assert_eq!(
            store.epoch_profiles(6),
            Err(SnapshotError::DuplicateProfile(key(1)))
        );
    }
}
