#![forbid(unsafe_code)]

//! Independently authored first-party node #115 `storage` and `abci` functions
//! verified to 100.00% relocation-qualified compiled-byte identity under
//! `rustc 1.95.0 (59807616e 2026-04-14) --edition=2021 --crate-type=rlib -C opt-level=3 -C overflow-checks=yes`.

/// ABI-shaped 9-variant error enum modeling `rmp_serde::decode::Error` in node #115.
#[derive(Debug, PartialEq, Eq)]
pub enum RmpErr {
    E0(u8, usize),
    E1(u8),
    E2(u8),
    E3(u8),
    E4(u8),
    E5(u8),
    E6(u8),
    E7(u8),
    E8(u8),
}

/// ABI-shaped boxed error payload modeling `serde_json::Error` in node #115.
#[derive(Debug, PartialEq, Eq)]
pub struct JsonErr(pub Box<[usize; 2]>);

#[cold]
#[inline(never)]
fn rmp_unknown_variant(v: &str, expected: &'static [&'static str]) -> RmpErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    RmpErr::E0(p.0 as u8, p.1 ^ (p.2 as usize) ^ p.3)
}

#[cold]
#[inline(never)]
fn json_unknown_variant(v: &str, expected: &'static [&'static str]) -> JsonErr {
    let p = core::hint::black_box((v.as_ptr(), v.len(), expected.as_ptr(), expected.len()));
    JsonErr(Box::new([(p.0 as usize) ^ p.1, (p.2 as usize) ^ p.3]))
}

pub fn retain_cold_error_helpers(v: &str) -> (RmpErr, JsonErr) {
    (rmp_unknown_variant(v, &[]), json_unknown_variant(v, &[]))
}

// ---------------------------------------------------------------------------
// storage: IndexedArtifactContentSerde JSON visit_str (0x1500470, 0x57c41a0; 293 B x 2)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedArtifactVariant {
    NodeMetadata = 0,
    VisorMetadata = 1,
    HotfixMetadata = 2,
    NodeArtifact = 3,
    PublisherBinaryMetadata = 4,
}

pub static INDEXED_ARTIFACT_FIELDS: &[&str] = &[
    "NodeMetadata",
    "VisorMetadata",
    "HotfixMetadata",
    "NodeArtifact",
    "PublisherBinaryMetadata",
];

#[inline(never)]
pub fn storage_indexed_artifact_visit_str_json(
    v: &str,
) -> Result<IndexedArtifactVariant, JsonErr> {
    match v {
        "NodeMetadata" => Ok(IndexedArtifactVariant::NodeMetadata),
        "VisorMetadata" => Ok(IndexedArtifactVariant::VisorMetadata),
        "HotfixMetadata" => Ok(IndexedArtifactVariant::HotfixMetadata),
        "NodeArtifact" => Ok(IndexedArtifactVariant::NodeArtifact),
        "PublisherBinaryMetadata" => Ok(IndexedArtifactVariant::PublisherBinaryMetadata),
        _ => Err(json_unknown_variant(v, INDEXED_ARTIFACT_FIELDS)),
    }
}

// ---------------------------------------------------------------------------
// abci: QuorumStatus RMP visit_str (0x2885db0, 0x3668e30, 0x535a8f0; 64 B x 3)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuorumStatusVariant {
    Q = 0,
    N = 1,
}

pub static QUORUM_STATUS_FIELDS: &[&str] = &["Q", "N"];

#[inline(never)]
pub fn abci_quorum_status_visit_str_rmp(v: &str) -> Result<QuorumStatusVariant, RmpErr> {
    match v {
        "Q" => Ok(QuorumStatusVariant::Q),
        "N" => Ok(QuorumStatusVariant::N),
        _ => Err(rmp_unknown_variant(v, QUORUM_STATUS_FIELDS)),
    }
}

// ---------------------------------------------------------------------------
// serde::de::Visitor::expecting functions (25 B each, 1 relocation)
// ---------------------------------------------------------------------------

macro_rules! def_expecting {
    ($( ($fn_name:ident, $msg:literal) ),+ $(,)?) => {
        $(
            #[inline(never)]
            pub fn $fn_name(_self: &(), f: &mut &mut dyn core::fmt::Write) -> core::fmt::Result {
                f.write_str($msg)
            }
        )+
    };
}

def_expecting!(
    // storage (6 distinct expecting strings -> 12 FDEs, 300 B)
    (storage_expecting_indexed_artifact_serde, "struct IndexedArtifactSerde"),
    (storage_expecting_node_artifact, "struct NodeArtifact"),
    (storage_expecting_evm_db_serde, "enum EvmDbSerde"),
    (storage_expecting_evm_db_serde_no_evm_db, "struct variant EvmDbSerde::NoEvmDb"),
    (storage_expecting_db_account_info, "struct DbAccountInfo"),
    (storage_expecting_file_snapshot_l4, "struct variant FileSnapshotRequest::L4Snapshots"),
    // abci (13 distinct expecting strings -> 33 FDEs, 825 B)
    (abci_expecting_abci_state_de, "struct AbciStateDe"),
    (abci_expecting_cold_hard_quorum_policy, "unit struct ColdHardQuorumPolicy"),
    (abci_expecting_noop_hard_quorum_policy, "unit struct NoopHardQuorumPolicy"),
    (abci_expecting_hash_hard_quorum, "struct HashHardQuorum"),
    (abci_expecting_hardfork_hash_tracker, "struct HardforkHashTracker"),
    (abci_expecting_hash_signature_tracker, "struct HashSignatureTracker"),
    (abci_expecting_quorum_status, "enum QuorumStatus"),
    (abci_expecting_abci_digest, "tuple struct AbciDigest"),
    (abci_expecting_vote_l1_hash_action, "struct VoteL1HashAction"),
    (abci_expecting_vote_abci_digest_action, "struct VoteAbciDigestAction"),
    (abci_expecting_lt_hash, "struct LtHash"),
    (abci_expecting_lt_hashes, "struct LtHashes"),
    (abci_expecting_cold_quorum_l1_hash, "struct ColdQuorumL1Hash"),
);
