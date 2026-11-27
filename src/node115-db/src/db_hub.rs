//! Node #115 `db/src/db_hub.rs` byte-key routing, offline typed key/value hub,
//! 32-byte MsgPack storage-value decoding, and snapshot selector admission.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`, `RE-009-node115-db-hub-routing-and-abci-schema`):
//! - `0x38b3ad0..0x38b3f8c`, `0x4e33ef0..0x4e342a5` (`db_hub.rs:25:38`)
//! - `0x3d4c7c0..0x3d4d420`, `0x57c58d0..0x57c6530` (`db_hub.rs:51:18`: 29-kind 3-shard routing + `.data.rel.ro 0x6479df0`)
//! - `0x1692ca0..0x1692fe9` (`db_hub.rs:62/66/68`)

use std::collections::BTreeMap;

pub use node115_db_hub_byte_key::{LayoutError, Lookup as ByteKeyLookup, Node as ByteKeyNode, lookup as byte_key_lookup};
pub use node115_storage_value_decode::{Decoded as DecodedStorageValue, InvalidValue, decode as decode_storage_value};

/// Bitmask for `DbHub` shard `0` (`r13b = 0`) observed at `0x3d4c7e5` and `0x57c58f5`.
pub const DB_HUB_SHARD_0_MASK: u32 = 0x031f_feff;

/// Bitmask for `DbHub` shard `1` (`r13b = 1`) observed at `0x3d4c825` and `0x57c5935`.
pub const DB_HUB_SHARD_1_MASK: u32 = 0x00e0_0100;

/// Core L1 tier upper index bound (`cmp bpl, 0x14`) observed at `0x3d4c7fa` and `0x57c590a`.
pub const DB_HUB_CORE_TIER_MAX_INDEX: u8 = 0x14;

/// All 29 `DbHub` logical table kinds backed by the `.data.rel.ro 0x6479df0` 2-byte prefix table
/// (`.rodata 0x7bd4ed..0x7bd527`) and 3-shard bitmask router in `db/src/db_hub.rs:51`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DbKind {
    Candle = 0,
    FundingLedgerUpdates = 1,
    NonFundingLedgerUpdates = 2,
    BoleInterest = 3,
    KindPs = 4,
    UserFills = 5,
    AssetTrades = 6,
    LegacyRewardHistory = 7,
    ExplorerUserTxs = 8,
    FundingHistory = 9,
    AssetCtxHistory = 10,
    OrderHistory = 11,
    UserTwapSliceFills = 12,
    TwapHistory = 13,
    UserPositionSamples = 14,
    UserAggregatedFills = 15,
    SpotEvents = 16,
    GovProposals = 17,
    DelegatorEvents = 18,
    DelegatorRewardHistory = 19,
    ValidatorBucketStats = 20,
    EvmTxs = 21,
    EvmBlockNumbers = 22,
    EvmBlocks = 23,
    SettledOutcomes = 24,
    KindSq = 25,
    EvmStateAccounts = 26,
    EvmStateContracts = 27,
    EvmStateStorage = 28,
}

impl DbKind {
    pub const ALL: [Self; 29] = [
        Self::Candle,
        Self::FundingLedgerUpdates,
        Self::NonFundingLedgerUpdates,
        Self::BoleInterest,
        Self::KindPs,
        Self::UserFills,
        Self::AssetTrades,
        Self::LegacyRewardHistory,
        Self::ExplorerUserTxs,
        Self::FundingHistory,
        Self::AssetCtxHistory,
        Self::OrderHistory,
        Self::UserTwapSliceFills,
        Self::TwapHistory,
        Self::UserPositionSamples,
        Self::UserAggregatedFills,
        Self::SpotEvents,
        Self::GovProposals,
        Self::DelegatorEvents,
        Self::DelegatorRewardHistory,
        Self::ValidatorBucketStats,
        Self::EvmTxs,
        Self::EvmBlockNumbers,
        Self::EvmBlocks,
        Self::SettledOutcomes,
        Self::KindSq,
        Self::EvmStateAccounts,
        Self::EvmStateContracts,
        Self::EvmStateStorage,
    ];

    /// Exact 2-byte RocksDB key prefix loaded from `0x6479df0[kind * 8]` (`.rodata 0x7bd4ed`).
    pub const fn prefix_bytes(self) -> &'static [u8; 2] {
        match self {
            Self::Candle => b"cA",
            Self::FundingLedgerUpdates => b"lu",
            Self::NonFundingLedgerUpdates => b"nf",
            Self::BoleInterest => b"bi",
            Self::KindPs => b"Ps",
            Self::UserFills => b"uf",
            Self::AssetTrades => b"aT",
            Self::LegacyRewardHistory => b"rh",
            Self::ExplorerUserTxs => b"et",
            Self::FundingHistory => b"fH",
            Self::AssetCtxHistory => b"aH",
            Self::OrderHistory => b"oh",
            Self::UserTwapSliceFills => b"ts",
            Self::TwapHistory => b"th",
            Self::UserPositionSamples => b"up",
            Self::UserAggregatedFills => b"ua",
            Self::SpotEvents => b"se",
            Self::GovProposals => b"gP",
            Self::DelegatorEvents => b"de",
            Self::DelegatorRewardHistory => b"dr",
            Self::ValidatorBucketStats => b"vb",
            Self::EvmTxs => b"Et",
            Self::EvmBlockNumbers => b"En",
            Self::EvmBlocks => b"Eb",
            Self::SettledOutcomes => b"so",
            Self::KindSq => b"sq",
            Self::EvmStateAccounts => b"Ea",
            Self::EvmStateContracts => b"Ec",
            Self::EvmStateStorage => b"Es",
        }
    }

    /// Exact 3-shard RocksDB handle selector (`0`, `1`, `2`) proven at `0x3d4c7e5`, `0x3d4c825`, `0x3d4cacb`.
    pub const fn shard_id(self) -> u8 {
        let bit = 1u32 << (self as u8);
        if (DB_HUB_SHARD_0_MASK & bit) != 0 {
            0
        } else if (DB_HUB_SHARD_1_MASK & bit) != 0 {
            1
        } else {
            2
        }
    }

    /// Exact core-tier predicate `kind <= 0x14` (`0x3d4c7fa` / `0x57c590a`).
    pub const fn is_core_l1_tier(self) -> bool {
        (self as u8) <= DB_HUB_CORE_TIER_MAX_INDEX
    }

    /// Construct the 2-byte-prefixed RocksDB key (`prefix || suffix`).
    pub fn prefixed_key(self, suffix: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + suffix.len());
        key.extend_from_slice(self.prefix_bytes());
        key.extend_from_slice(suffix);
        key
    }
}

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

    /// Route a logical `DbKind` write into its binary-proven shard (`0`/`1`/`2`)
    /// with its 2-byte prefix (`0x6479df0[kind * 8]`).
    pub fn put_kind(&mut self, kind: DbKind, suffix: &[u8], value: Vec<u8>) {
        self.put(kind.shard_id(), kind.prefixed_key(suffix), value);
    }

    /// Route a logical `DbKind` read from its binary-proven shard (`0`/`1`/`2`)
    /// with its 2-byte prefix (`0x6479df0[kind * 8]`).
    pub fn get_kind(&self, kind: DbKind, suffix: &[u8]) -> Option<&[u8]> {
        self.get(kind.shard_id(), &kind.prefixed_key(suffix))
    }
}
