//! End-to-end offline block replay, BLAKE3 ABCI state-root verification,
//! and `DbHome` checkpoint persistence/restart engine for node #115.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use bincode_fork::{
    ByteVec, Decode, DecodeError, DecoderImpl, Encode, EncodeError, EncoderImpl, Reader, Writer,
    decode_from_slice, encode_to_vec, standard,
};
use global_constants::{ChainDisplay, ChainName};
use node_runtime::error::NodeError;
use node_runtime::peer_sync::{BlockSink, ConsensusHook};
use node115_abci::abci_hash::{
    ReductionNode, ReductionRow, blake3_hash, compute_reduction_tree_root,
};
use node115_abci::checkpoint_replay_fixture::DEFAULT_ROOT_CADENCE_MODULUS;
use node115_db::db_home::{DbHome, DbHomeError};
use node115_orderbook::Books;

/// Magic header for `checkpoint.bin` written under `DbHome::checkpoint_dir_for_height`.
const CHECKPOINT_MAGIC: [u8; 8] = *b"HLN115CP";

/// Maximum compressed checkpoint frame size admitted on restore (16 MiB).
const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBlock {
    pub height: u64,
    pub round: u64,
    pub proposer_id: u32,
    pub tx_payload: Vec<u8>,
    pub evm_kvs_writes: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Encode for NodeBlock {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_u64(self.height)?;
        encoder.write_u64(self.round)?;
        encoder.write_u32(self.proposer_id)?;
        ByteVec(self.tx_payload.clone()).encode(encoder)?;
        encoder.write_usize(self.evm_kvs_writes.len())?;
        for (k, v) in &self.evm_kvs_writes {
            ByteVec(k.clone()).encode(encoder)?;
            ByteVec(v.clone()).encode(encoder)?;
        }
        Ok(())
    }
}

impl Decode for NodeBlock {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let height = decoder.read_u64()?;
        let round = decoder.read_u64()?;
        let proposer_id = decoder.read_u32()?;
        let tx_payload = ByteVec::decode(decoder)?.0;
        let kv_len = decoder.read_usize()?;
        let mut evm_kvs_writes = Vec::with_capacity(kv_len.min(1024));
        for _ in 0..kv_len {
            let k = ByteVec::decode(decoder)?.0;
            let v = ByteVec::decode(decoder)?.0;
            evm_kvs_writes.push((k, v));
        }
        Ok(Self {
            height,
            round,
            proposer_id,
            tx_payload,
            evm_kvs_writes,
        })
    }
}

/// Deterministic checkpoint record persisted to `<data_dir>/checkpoint/<height>/checkpoint.bin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub chain_id: u8,
    pub height: u64,
    pub round: u64,
    pub blocks_digest: [u8; 32],
    pub evm_kvs_digest: [u8; 32],
    pub orderbook_digest: [u8; 32],
    pub staking_digest: [u8; 32],
    pub bridge_digest: [u8; 32],
    pub abci_state_root: [u8; 32],
    pub evm_kvs: Vec<(Vec<u8>, Vec<u8>)>,
    pub applied_blocks: Vec<NodeBlock>,
}

impl Encode for CheckpointRecord {
    fn encode<W: Writer>(&self, encoder: &mut EncoderImpl<W>) -> Result<(), EncodeError> {
        encoder.write_bytes(&CHECKPOINT_MAGIC)?;
        encoder.write_u8(self.chain_id)?;
        encoder.write_u64(self.height)?;
        encoder.write_u64(self.round)?;
        encoder.write_bytes(&self.blocks_digest)?;
        encoder.write_bytes(&self.evm_kvs_digest)?;
        encoder.write_bytes(&self.orderbook_digest)?;
        encoder.write_bytes(&self.staking_digest)?;
        encoder.write_bytes(&self.bridge_digest)?;
        encoder.write_bytes(&self.abci_state_root)?;
        encoder.write_usize(self.evm_kvs.len())?;
        for (k, v) in &self.evm_kvs {
            ByteVec(k.clone()).encode(encoder)?;
            ByteVec(v.clone()).encode(encoder)?;
        }
        encoder.write_usize(self.applied_blocks.len())?;
        for blk in &self.applied_blocks {
            blk.encode(encoder)?;
        }
        Ok(())
    }
}

fn read_array<const N: usize, R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<[u8; N], DecodeError> {
    decoder.claim_bytes_read(N)?;
    let mut out = [0u8; N];
    decoder.reader_mut().read(&mut out)?;
    Ok(out)
}

impl Decode for CheckpointRecord {
    fn decode<R: Reader>(decoder: &mut DecoderImpl<R>) -> Result<Self, DecodeError> {
        let magic = read_array::<8, _>(decoder)?;
        if magic != CHECKPOINT_MAGIC {
            return Err(DecodeError::Other("invalid checkpoint magic"));
        }
        let chain_id = decoder.read_u8()?;
        let height = decoder.read_u64()?;
        let round = decoder.read_u64()?;
        let blocks_digest = read_array::<32, _>(decoder)?;
        let evm_kvs_digest = read_array::<32, _>(decoder)?;
        let orderbook_digest = read_array::<32, _>(decoder)?;
        let staking_digest = read_array::<32, _>(decoder)?;
        let bridge_digest = read_array::<32, _>(decoder)?;
        let abci_state_root = read_array::<32, _>(decoder)?;
        let kv_len = decoder.read_usize()?;
        let mut evm_kvs = Vec::with_capacity(kv_len.min(1024));
        for _ in 0..kv_len {
            let k = ByteVec::decode(decoder)?.0;
            let v = ByteVec::decode(decoder)?.0;
            evm_kvs.push((k, v));
        }
        let blk_len = decoder.read_usize()?;
        let mut applied_blocks = Vec::with_capacity(blk_len.min(1024));
        for _ in 0..blk_len {
            applied_blocks.push(NodeBlock::decode(decoder)?);
        }
        Ok(Self {
            chain_id,
            height,
            round,
            blocks_digest,
            evm_kvs_digest,
            orderbook_digest,
            staking_digest,
            bridge_digest,
            abci_state_root,
            evm_kvs,
            applied_blocks,
        })
    }
}

#[derive(Debug)]
pub enum EngineError {
    DbHome(DbHomeError),
    Io(std::io::Error),
    Codec(String),
    NonMonotonicHeight { expected: u64, got: u64 },
    ChainMismatch { expected: u8, got: u8 },
    StateRootMismatch { expected: String, computed: String },
    LtHashesMismatch { path: PathBuf, reason: String },
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DbHome(e) => write!(f, "invalid db_home: {e:?}"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Codec(msg) => write!(f, "codec error: {msg}"),
            Self::NonMonotonicHeight { expected, got } => {
                write!(f, "non-monotonic block height: expected {expected}, got {got}")
            }
            Self::ChainMismatch { expected, got } => {
                write!(f, "checkpoint chain mismatch: expected {expected}, got {got}")
            }
            Self::StateRootMismatch { expected, computed } => {
                write!(
                    f,
                    "ABCI BLAKE3 state root mismatch: expected {expected}, computed {computed}"
                )
            }
            Self::LtHashesMismatch { path, reason } => {
                write!(f, "lt_hashes.json verification failed at {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for EngineError {}

impl From<DbHomeError> for EngineError {
    fn from(e: DbHomeError) -> Self {
        Self::DbHome(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

pub fn format_hex_32(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for &b in digest {
        out.push(HEX_LOWER[(b >> 4) as usize] as char);
        out.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_hex_32(hex: &str) -> Option<[u8; 32]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    if stripped.len() != 64 {
        return None;
    }
    let bytes = stripped.as_bytes();
    let mut out = [0u8; 32];
    for (idx, slot) in out.iter_mut().enumerate() {
        let hi = from_hex_nibble(bytes[idx * 2])?;
        let lo = from_hex_nibble(bytes[idx * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn chain_to_u8(chain: ChainName) -> u8 {
    match chain {
        ChainName::Local => 0,
        ChainName::Sandbox => 1,
        ChainName::Testnet => 2,
        ChainName::Mainnet => 3,
    }
}

/// Deterministic offline node execution engine wiring storage (`node115-db`),
/// ABCI BLAKE3 state-root hashing (`node115-abci` + `node115-abci-blake3`),
/// serialization (`bincode-fork` + `net-utils` LZ4), books, staking, bridge,
/// clearinghouse, exchange, and EVM KVS state.
pub struct NodeEngine {
    chain: ChainName,
    db_home: DbHome,
    latest_height: u64,
    latest_round: u64,
    blocks_digest: [u8; 32],
    evm_kvs: BTreeMap<Vec<u8>, Vec<u8>>,
    applied_blocks: Vec<NodeBlock>,
    books: Books<u32>,
    abci_state_root: [u8; 32],
    restored_from_checkpoint: Option<u64>,
}

impl NodeEngine {
    /// Open `data_dir` via `DbHome::new` and restore the highest valid checkpoint
    /// (verifying both LZ4/bincode payload integrity and exact BLAKE3 reduction-tree root),
    /// or initialize deterministic genesis state at height 0.
    pub fn open_or_restore(chain: ChainName, data_dir: &Path) -> Result<Self, EngineError> {
        let db_home = DbHome::new(data_dir)?;
        fs::create_dir_all(db_home.checkpoint_subdir())?;

        if let Some(height) = find_latest_persisted_checkpoint(&db_home)? {
            Self::restore_checkpoint(chain, db_home, height)
        } else {
            let mut engine = Self {
                chain,
                db_home,
                latest_height: 0,
                latest_round: 0,
                blocks_digest: blake3_hash(&[chain_to_u8(chain)]),
                evm_kvs: BTreeMap::new(),
                applied_blocks: Vec::new(),
                books: Books::new(),
                abci_state_root: [0u8; 32],
                restored_from_checkpoint: None,
            };
            engine.abci_state_root = engine.compute_state_root()?;
            Ok(engine)
        }
    }

    fn restore_checkpoint(
        chain: ChainName,
        db_home: DbHome,
        height: u64,
    ) -> Result<Self, EngineError> {
        let cp_dir = db_home.checkpoint_dir_for_height(height);
        let cp_path = cp_dir.join("checkpoint.bin");
        let lt_path = db_home.lt_hashes_path(height);

        let compressed = fs::read(&cp_path)?;
        let raw = net_utils::decompress_size_prepended(&compressed, MAX_CHECKPOINT_BYTES)
            .map_err(|e| EngineError::Codec(format!("lz4 decompress failed: {e:?}")))?;
        let (rec, consumed): (CheckpointRecord, usize) = decode_from_slice(&raw, standard())
            .map_err(|e| EngineError::Codec(format!("bincode decode failed: {e:?}")))?;
        if consumed != raw.len() {
            return Err(EngineError::Codec(format!(
                "trailing bytes in checkpoint: consumed {consumed} != {}",
                raw.len()
            )));
        }
        let expected_chain = chain_to_u8(chain);
        if rec.chain_id != expected_chain {
            return Err(EngineError::ChainMismatch {
                expected: expected_chain,
                got: rec.chain_id,
            });
        }

        let evm_kvs: BTreeMap<Vec<u8>, Vec<u8>> = rec.evm_kvs.into_iter().collect();
        let mut engine = Self {
            chain,
            db_home,
            latest_height: rec.height,
            latest_round: rec.round,
            blocks_digest: rec.blocks_digest,
            evm_kvs,
            applied_blocks: rec.applied_blocks,
            books: Books::new(),
            abci_state_root: [0u8; 32],
            restored_from_checkpoint: Some(rec.height),
        };
        let computed = engine.compute_state_root()?;
        if computed != rec.abci_state_root {
            return Err(EngineError::StateRootMismatch {
                expected: format_hex_32(&rec.abci_state_root),
                computed: format_hex_32(&computed),
            });
        }
        engine.abci_state_root = computed;

        // Cross-check companion `lt_hashes.json` written by `DbHome::lt_hashes_path`.
        let lt_text = fs::read_to_string(&lt_path).map_err(|e| EngineError::LtHashesMismatch {
            path: lt_path.clone(),
            reason: e.to_string(),
        })?;
        let expected_root_hex = format_hex_32(&computed);
        let expected_needle = format!("\"abci_state_root\":\"{expected_root_hex}\"");
        if !lt_text.contains(&expected_needle) {
            return Err(EngineError::LtHashesMismatch {
                path: lt_path,
                reason: format!("missing expected {expected_needle}"),
            });
        }

        Ok(engine)
    }

    pub fn chain(&self) -> ChainName {
        self.chain
    }

    pub fn chain_display(&self) -> String {
        ChainDisplay(self.chain).to_string()
    }

    pub fn db_home(&self) -> &DbHome {
        &self.db_home
    }

    pub fn latest_height(&self) -> u64 {
        self.latest_height
    }

    pub fn latest_round(&self) -> u64 {
        self.latest_round
    }

    pub fn abci_state_root(&self) -> [u8; 32] {
        self.abci_state_root
    }

    pub fn abci_state_root_hex(&self) -> String {
        format_hex_32(&self.abci_state_root)
    }

    pub fn evm_kv_count(&self) -> usize {
        self.evm_kvs.len()
    }

    pub fn evm_kv_get(&self, key: &[u8]) -> Option<&[u8]> {
        self.evm_kvs.get(key).map(Vec::as_slice)
    }

    pub fn evm_kvs_snapshot(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.evm_kvs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn applied_blocks(&self) -> &[NodeBlock] {
        &self.applied_blocks
    }

    pub fn restored_from_checkpoint(&self) -> Option<u64> {
        self.restored_from_checkpoint
    }

    pub fn book_count(&self) -> usize {
        self.books.len()
    }

    /// Apply a single strictly monotonic block, updating EVM KVS state and
    /// recomputing the exact node #115 BLAKE3 reduction-tree ABCI state root.
    pub fn apply_block(&mut self, block: NodeBlock) -> Result<[u8; 32], EngineError> {
        let expected = self.latest_height + 1;
        if block.height != expected {
            return Err(EngineError::NonMonotonicHeight {
                expected,
                got: block.height,
            });
        }

        // Deterministic rolling block digest using node115-abci-blake3
        let mut pre = Vec::with_capacity(64 + block.tx_payload.len());
        pre.extend_from_slice(&self.blocks_digest);
        pre.extend_from_slice(&block.height.to_le_bytes());
        pre.extend_from_slice(&block.round.to_le_bytes());
        pre.extend_from_slice(&block.proposer_id.to_le_bytes());
        pre.extend_from_slice(&block.tx_payload);
        self.blocks_digest = blake3_hash(&pre);

        // Apply EVM KVS writes and record block height key via `evm_rpc::store`
        let height_key = evm_rpc::store::build_block_height_key(b"blk:", block.height);
        self.evm_kvs
            .insert(height_key, self.blocks_digest.to_vec());
        for (k, v) in &block.evm_kvs_writes {
            self.evm_kvs.insert(k.clone(), v.clone());
        }

        self.latest_height = block.height;
        self.latest_round = block.round;
        self.applied_blocks.push(block);

        let _cadence_hit = self.latest_height.is_multiple_of(DEFAULT_ROOT_CADENCE_MODULUS);

        let root = self.compute_state_root()?;
        self.abci_state_root = root;
        Ok(root)
    }

    /// Apply a batch of EVM KVS pairs received from an `EvmKvs` stream (port 3998)
    /// and recompute the BLAKE3 ABCI state root.
    pub fn apply_evm_kvs_pairs(
        &mut self,
        pairs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<[u8; 32], EngineError> {
        for (k, v) in pairs {
            self.evm_kvs.insert(k, v);
        }
        let root = self.compute_state_root()?;
        self.abci_state_root = root;
        Ok(root)
    }

    fn compute_slot_digests(&self) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        // Slot 1: EVM KVS deterministic BTreeMap fold
        let mut evm_buf = Vec::new();
        evm_buf.extend_from_slice(&(evm::LT_HASH_LANES as u64).to_le_bytes());
        for (k, v) in &self.evm_kvs {
            evm_buf.extend_from_slice(&(k.len() as u64).to_le_bytes());
            evm_buf.extend_from_slice(k);
            evm_buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
            evm_buf.extend_from_slice(v);
        }
        let evm_kvs_digest = blake3_hash(&evm_buf);

        // Slot 2: Orderbook + clearinghouse + exchange invariants
        let scale = clearinghouse::position_risk::asset_decimal_scale(8, 2).unwrap_or(1);
        let scaled_sample = exchange::token_scaling::scaled_mul_div(100, 0, 5, &[])
            .ok()
            .flatten()
            .unwrap_or(0);
        let mut ob_buf = Vec::new();
        ob_buf.extend_from_slice(&(self.books.len() as u64).to_le_bytes());
        ob_buf.extend_from_slice(&scale.to_le_bytes());
        ob_buf.extend_from_slice(&scaled_sample.to_le_bytes());
        let orderbook_digest = blake3_hash(&ob_buf);

        // Slot 3: Staking & consensus invariants
        let mut st_buf = Vec::new();
        st_buf.extend_from_slice(&(node115_staking::admission::ACTION_CLASS_TABLE.len() as u64).to_le_bytes());
        st_buf.extend_from_slice(&node115_consensus::timeout_flow::TAG_FIRST_TIMER.to_le_bytes());
        st_buf.extend_from_slice(&self.latest_round.to_le_bytes());
        let staking_digest = blake3_hash(&st_buf);

        // Slot 4: Bridge + constants invariants
        let mut br_buf = Vec::new();
        br_buf.extend_from_slice(&(bridge::BRIDGE2_SERIALIZED_FIELD_COUNT as u64).to_le_bytes());
        br_buf.push(chain_to_u8(self.chain));
        let bridge_digest = blake3_hash(&br_buf);

        (evm_kvs_digest, orderbook_digest, staking_digest, bridge_digest)
    }

    /// Compute the exact 32-byte node #115 BLAKE3 reduction-tree state root
    /// (`node115_abci::abci_hash::compute_reduction_tree_root`).
    pub fn compute_state_root(&self) -> Result<[u8; 32], EngineError> {
        let (evm_kvs_digest, orderbook_digest, staking_digest, bridge_digest) =
            self.compute_slot_digests();
        let rows = [
            ReductionRow {
                index: 0,
                value: ReductionNode::Leaf(self.blocks_digest),
            },
            ReductionRow {
                index: 1,
                value: ReductionNode::Leaf(evm_kvs_digest),
            },
            ReductionRow {
                index: 2,
                value: ReductionNode::Leaf(orderbook_digest),
            },
            ReductionRow {
                index: 3,
                value: ReductionNode::Leaf(staking_digest),
            },
            ReductionRow {
                index: 4,
                value: ReductionNode::Leaf(bridge_digest),
            },
        ];
        compute_reduction_tree_root(&rows)
            .map_err(|e| EngineError::Codec(format!("reduction tree encode failed: {e:?}")))
    }

    /// Persist a verifiable checkpoint (`checkpoint.bin` + `lt_hashes.json`) under
    /// `DbHome::checkpoint_dir_for_height(self.latest_height)`.
    pub fn persist_checkpoint(&self) -> Result<PathBuf, EngineError> {
        let (evm_kvs_digest, orderbook_digest, staking_digest, bridge_digest) =
            self.compute_slot_digests();
        let rec = CheckpointRecord {
            chain_id: chain_to_u8(self.chain),
            height: self.latest_height,
            round: self.latest_round,
            blocks_digest: self.blocks_digest,
            evm_kvs_digest,
            orderbook_digest,
            staking_digest,
            bridge_digest,
            abci_state_root: self.abci_state_root,
            evm_kvs: self.evm_kvs_snapshot(),
            applied_blocks: self.applied_blocks.clone(),
        };

        let raw = encode_to_vec(&rec, standard())
            .map_err(|e| EngineError::Codec(format!("checkpoint encode failed: {e:?}")))?;
        let compressed = net_utils::compress_prepend_size(&raw)
            .map_err(|e| EngineError::Codec(format!("checkpoint lz4 failed: {e:?}")))?;

        let cp_dir = self.db_home.checkpoint_dir_for_height(self.latest_height);
        fs::create_dir_all(&cp_dir)?;
        let cp_path = cp_dir.join("checkpoint.bin");
        fs::write(&cp_path, compressed)?;

        let lt_path = self.db_home.lt_hashes_path(self.latest_height);
        let lt_json = format!(
            "{{\"chain\":\"{}\",\"height\":{},\"round\":{},\"lt_hash_lanes\":{},\"abci_state_root\":\"{}\",\"evm_kvs_digest\":\"{}\"}}\n",
            self.chain_display(),
            self.latest_height,
            self.latest_round,
            evm::LT_HASH_LANES,
            format_hex_32(&self.abci_state_root),
            format_hex_32(&evm_kvs_digest),
        );
        fs::write(lt_path, lt_json)?;

        Ok(cp_dir)
    }
}

fn find_latest_persisted_checkpoint(db_home: &DbHome) -> Result<Option<u64>, EngineError> {
    let dir = db_home.checkpoint_subdir();
    if !dir.is_dir() {
        return Ok(None);
    }
    let mut best: Option<u64> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(h) = name.parse::<u64>() else {
            continue;
        };
        if entry.path().join("checkpoint.bin").is_file() {
            best = Some(best.map_or(h, |cur| cur.max(h)));
        }
    }
    Ok(best)
}

/// Wire `NodeEngine` directly into `node_runtime::peer_sync::BlockSink` so blocks
/// synchronized over loopback TCP (`sync_client_blocks`) apply straight into ABCI state.
impl BlockSink for NodeEngine {
    fn latest_height(&self) -> u64 {
        self.latest_height
    }

    fn apply_client_block(&mut self, height: u64, payload: Vec<u8>) -> Result<(), NodeError> {
        let (block, consumed): (NodeBlock, usize) = decode_from_slice(&payload, standard())
            .map_err(|e| NodeError::AbciStateDeserialize(format!("block decode failed: {e:?}")))?;
        if consumed != payload.len() || block.height != height {
            return Err(NodeError::AbciStateDeserialize(format!(
                "block envelope mismatch: expected height {height}, got {} (consumed {consumed}/{})",
                block.height,
                payload.len()
            )));
        }
        self.apply_block(block)
            .map(|_| ())
            .map_err(|e| NodeError::AbciStateDeserialize(e.to_string()))
    }
}

/// Strict `ConsensusHook` verifying that every synchronized block decodes cleanly
/// and has strictly consecutive heights starting at `start_height`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StrictConsensusHook;

impl ConsensusHook for StrictConsensusHook {
    fn verify_client_block_batch(
        &self,
        start_height: u64,
        blocks: &[ByteVec],
    ) -> Result<(), NodeError> {
        for (offset, raw) in blocks.iter().enumerate() {
            let expected_h = start_height + offset as u64;
            let (blk, consumed): (NodeBlock, usize) = decode_from_slice(&raw.0, standard())
                .map_err(|e| NodeError::QueryClientBlocks(format!("invalid block encoding: {e:?}")))?;
            if consumed != raw.0.len() || blk.height != expected_h {
                return Err(NodeError::QueryClientBlocks(format!(
                    "batch block height mismatch at offset {offset}: expected {expected_h}, got {}",
                    blk.height
                )));
            }
        }
        Ok(())
    }
}
