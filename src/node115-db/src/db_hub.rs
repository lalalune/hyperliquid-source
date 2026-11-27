//! Node #115 `db/src/db_hub.rs` byte-key routing, offline typed key/value hub,
//! 32-byte MsgPack storage-value decoding, and snapshot selector admission.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`):
//! - `0x38b3ad0..0x38b3f8c`, `0x4e33ef0..0x4e342a5` (`db_hub.rs:25:38`)
//! - `0x3d4c7c0..0x3d4d420`, `0x57c58d0..0x57c6530` (`db_hub.rs:51:18`)
//! - `0x1692ca0..0x1692fe9` (`db_hub.rs:62/66/68`)

use std::collections::BTreeMap;

pub use node115_db_hub_byte_key::{LayoutError, Lookup as ByteKeyLookup, Node as ByteKeyNode, lookup as byte_key_lookup};
pub use node115_storage_value_decode::{Decoded as DecodedStorageValue, InvalidValue, decode as decode_storage_value};

const SNAPSHOT_ALL: u64 = 1 << 63;
const SNAPSHOT_SPECIAL: u64 = SNAPSHOT_ALL + 1;

/// Snapshot worker admission matching `src/node115-snapshot-selectors/lib.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotWorkerAdmission {
    AllCollection,
    LimitExit,
    Explicit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotWrapperKind {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotOuterPath {
    Special,
    Worker0,
    Worker1,
    Worker2,
    Worker3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotOuterSelection {
    pub path: SnapshotOuterPath,
    pub normalized_mode: u64,
}

pub fn snapshot_worker_admission(selector: u64, count: u64) -> SnapshotWorkerAdmission {
    if selector == SNAPSHOT_ALL {
        SnapshotWorkerAdmission::AllCollection
    } else if count >= 101 {
        SnapshotWorkerAdmission::LimitExit
    } else {
        SnapshotWorkerAdmission::Explicit
    }
}

pub fn snapshot_outer_selection(
    which: SnapshotWrapperKind,
    selector: u64,
    selector_byte: u8,
    raw_mode: u64,
) -> SnapshotOuterSelection {
    let normalized_mode = u64::from(raw_mode as u32 != 0);
    let nonzero = selector_byte != 0;
    let path = if selector == SNAPSHOT_SPECIAL {
        SnapshotOuterPath::Special
    } else {
        match (which, nonzero) {
            (SnapshotWrapperKind::First, true) => SnapshotOuterPath::Worker0,
            (SnapshotWrapperKind::First, false) => SnapshotOuterPath::Worker2,
            (SnapshotWrapperKind::Second, true) => SnapshotOuterPath::Worker3,
            (SnapshotWrapperKind::Second, false) => SnapshotOuterPath::Worker1,
        }
    };
    SnapshotOuterSelection {
        path,
        normalized_mode,
    }
}

/// Offline in-memory `DbHub` partitioned by byte-key namespace (matching `db_hub.rs` byte keys)
/// with native 32-byte MsgPack limb decoding via `node115-storage-value-decode`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OfflineDbHub {
    namespaces: BTreeMap<u8, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl OfflineDbHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, namespace: u8, key: Vec<u8>, value: Vec<u8>) {
        self.namespaces
            .entry(namespace)
            .or_default()
            .insert(key, value);
    }

    pub fn get(&self, namespace: u8, key: &[u8]) -> Option<&[u8]> {
        self.namespaces
            .get(&namespace)?
            .get(key)
            .map(Vec::as_slice)
    }

    pub fn get_u256_limbs(
        &self,
        namespace: u8,
        key: &[u8],
    ) -> Option<Result<DecodedStorageValue, InvalidValue>> {
        self.get(namespace, key).map(decode_storage_value)
    }

    pub fn namespace_count(&self) -> usize {
        self.namespaces.len()
    }
}
