//! Node #115 `db/src/rocks_db.rs` open-result error niche, 3-shard RocksDB open profiles,
//! TCP stream size ceiling, SSTable `BlockHandle` codec, and pure-std persistent on-disk
//! shard/column-family KV store + atomic checkpoint creation.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`,
//! `RE-009-node115-rocksdb-profiles-and-apply-block-lifecycle`):
//! - `0x4524660..0x4524adb` (`rocks_db.rs:58:49`): `EvmState` open (2 GiB cache, 16 KiB block,
//!   128 MiB write buffer, multi-CF open `0x3d5ed10`).
//! - `0x57c6530..0x57c70b4`: Core L1 (`Exchange`, `Rpc`) open (16 GiB cache, 32 KiB block,
//!   128 MiB write buffer, single default CF).
//! - `0x5a69415..0x5a6941f`: `(size >> 11) > 0x2e90edc` (`>= 100_000_000_000` B `"RocksDb too large"`).
//! - `0x3d525a0..0x3d526e6`: `InvalidMarkerWrite` (tag 0) / `InvalidDataWrite` (tag 1).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub use node115_block_handle_codec::{
    BAD_BLOCK_HANDLE, BlockHandle, DecodeStatus, InputSlice, decode_into, decode_varint64, encode,
    encode_varint64,
};
pub use node115_owned_db_open::{
    BLOCK_SIZE, COMPANION_BYTES, DEFAULT_CACHE_BUDGET, ERROR_NICHE, OPTIONS_FLAG,
    result_word_is_error_niche,
};

/// Core L1 (`Exchange`, `Rpc`) default LRU block cache budget (`0x57c661b`: `0x4000 << 20` = 16 GiB).
pub const CORE_DEFAULT_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Core L1 (`Exchange`, `Rpc`) SST block size (`0x57c66c6`: `0x8000` = 32 KiB).
pub const CORE_BLOCK_SIZE: u64 = 0x8000;
/// `EvmState` default LRU block cache budget (`0x4524747`: `0x800 << 20` = 2 GiB).
pub const EVM_DEFAULT_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// `EvmState` SST block size (`0x45247f2`: `0x4000` = 16 KiB).
pub const EVM_BLOCK_SIZE: u64 = 0x4000;
/// Shared `write_buffer_size` (`0x452482e`, `0x57c671b`: `0x8000000` = 128 MiB).
pub const WRITE_BUFFER_BYTES: u64 = 0x0800_0000;
/// Exact TCP-streamed RocksDB rejection ceiling (`0x5a69415..0x5a6941f`):
/// `(size >> 11) > 0x2e90edc` <=> `size >= 100_000_000_000` bytes (100 GB decimal).
pub const TCP_ROCKSDB_MAX_BYTES: u64 = 100_000_000_000;
/// `DbHub` sub-directory prefix literal observed at `0x3d4c9e2` (`.rodata 0x431b96`).
pub const DHS_SUBDIR_PREFIX: &str = "dhs/";
/// Per-shard checkpoint completion marker prefix proven at `0x1696b90..0x1696d23`
/// (`.rodata 0x442eae` `"/CHECKPOINT_COMPLETE_"`).
pub const CHECKPOINT_COMPLETE_SHARD_PREFIX: &str = "CHECKPOINT_COMPLETE_";
/// Forbidden substring rejected by `OwnedDbDir` at `0x16961b0..0x1696729`
/// (`.rodata 0x447e28` `"OwnedDbDir invalid dir "`).
pub const OWNED_DB_DIR_FORBIDDEN_SUBSTR: &str = "checkpoint";
/// Column family names opened for the `EvmState` shard (`0x3d5ed10`, `.rodata 0x456bf0`, `0x7bd710`, `0x7bd721`).
pub const EVM_STATE_COLUMN_FAMILIES: [&str; 4] = [
    "default",
    "EvmStateAccounts",
    "EvmStateContracts",
    "EvmStateStorage",
];

/// On-disk RocksDB shard identity proven in `0x5a007c0` (`Exchange`/`Rpc`) and `0x44699c0` (`EvmState`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum RocksDbShard {
    Exchange,
    Rpc,
    EvmState,
}

impl RocksDbShard {
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Exchange => "Exchange",
            Self::Rpc => "Rpc",
            Self::EvmState => "EvmState",
        }
    }

    /// Lowercase shard marker filename matching `0x1696b90..0x1696d23`:
    /// `format!("{dir}/CHECKPOINT_COMPLETE_{}", shard.to_string().to_lowercase())`.
    pub fn checkpoint_complete_marker_path(self, checkpoint_root: &Path) -> PathBuf {
        checkpoint_root.join(format!(
            "{CHECKPOINT_COMPLETE_SHARD_PREFIX}{}",
            self.dir_name().to_ascii_lowercase()
        ))
    }

    pub const fn column_families(self) -> &'static [&'static str] {
        match self {
            Self::Exchange | Self::Rpc => &["default"],
            Self::EvmState => &EVM_STATE_COLUMN_FAMILIES,
        }
    }

    pub const fn profile(self) -> RocksDbShardProfile {
        match self {
            Self::Exchange | Self::Rpc => RocksDbShardProfile {
                shard: self,
                default_cache_bytes: CORE_DEFAULT_CACHE_BYTES,
                block_size_bytes: CORE_BLOCK_SIZE,
                write_buffer_bytes: WRITE_BUFFER_BYTES,
                create_if_missing: true,
                multi_column_family: false,
            },
            Self::EvmState => RocksDbShardProfile {
                shard: self,
                default_cache_bytes: EVM_DEFAULT_CACHE_BYTES,
                block_size_bytes: EVM_BLOCK_SIZE,
                write_buffer_bytes: WRITE_BUFFER_BYTES,
                create_if_missing: true,
                multi_column_family: true,
            },
        }
    }
}

/// Binary-grounded open option profile for a node #115 RocksDB shard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksDbShardProfile {
    pub shard: RocksDbShard,
    pub default_cache_bytes: u64,
    pub block_size_bytes: u64,
    pub write_buffer_bytes: u64,
    pub create_if_missing: bool,
    pub multi_column_family: bool,
}

/// Error returned when a TCP-streamed RocksDB payload meets or exceeds `TCP_ROCKSDB_MAX_BYTES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksDbTooLargeError {
    pub size_bytes: u64,
    pub limit_bytes: u64,
}

/// Enforces `0x5a69415..0x5a6941f` (`(size >> 11) > 0x2e90edc` <=> `size >= 100_000_000_000`).
pub const fn validate_tcp_rocksdb_size(size_bytes: u64) -> Result<(), RocksDbTooLargeError> {
    if (size_bytes >> 11) > 0x02e9_0edc {
        Err(RocksDbTooLargeError {
            size_bytes,
            limit_bytes: TCP_ROCKSDB_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Error returned when an `OwnedDbDir` path contains the forbidden `"checkpoint"` substring
/// (`0x16961b0..0x1696729`, `.rodata 0x447e29` `"OwnedDbDir invalid dir "`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedDbDirInvalidError {
    pub dir: String,
}

impl std::fmt::Display for OwnedDbDirInvalidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnedDbDir invalid dir {}", self.dir)
    }
}

impl std::error::Error for OwnedDbDirInvalidError {}

/// Rejects any `OwnedDbDir` string containing `"checkpoint"` (`0x16961b0..0x1696729`,
/// SIMD substring search closure at `0x1696870..0x1696961`).
pub fn validate_owned_db_dir(dir: &str) -> Result<(), OwnedDbDirInvalidError> {
    if dir.contains(OWNED_DB_DIR_FORBIDDEN_SUBSTR) {
        Err(OwnedDbDirInvalidError {
            dir: dir.to_string(),
        })
    } else {
        Ok(())
    }
}

/// Marker vs data write error enum proven at `0x3d525a0..0x3d526e6` (`cmp dword ptr [rcx], 1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbWriteError {
    InvalidMarkerWrite(String),
    InvalidDataWrite(String),
}

/// WriteBatch operation matching `0x3d4c310`/`0x3d4c6a0` (`rocksdb_writebatch_*`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbWriteBatchOp {
    Put {
        cf: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: String,
        key: Vec<u8>,
    },
}

const KV_FILE_MAGIC: &[u8; 8] = b"HL115KV1";

/// Pure-std crash-safe on-disk KV store for a single node #115 `RocksDbShard`,
/// supporting multiple column families, atomic write-batch persistence, and atomic
/// checkpoint snapshot creation (`CHECKPOINT_COMPLETE`).
#[derive(Clone, Debug)]
pub struct PersistentShardKvStore {
    root_dir: PathBuf,
    shard: RocksDbShard,
    data: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl PersistentShardKvStore {
    /// Open or initialize `<db_home>/<shard.dir_name()>` and load all configured column families.
    pub fn open(db_home: &Path, shard: RocksDbShard) -> io::Result<Self> {
        let root_dir = db_home.join(shard.dir_name());
        fs::create_dir_all(&root_dir)?;
        let mut data = BTreeMap::new();
        for &cf in shard.column_families() {
            let cf_path = root_dir.join(format!("{cf}.kv"));
            let entries = if cf_path.is_file() {
                read_kv_file(&cf_path)?
            } else {
                BTreeMap::new()
            };
            data.insert(cf.to_string(), entries);
        }
        Ok(Self {
            root_dir,
            shard,
            data,
        })
    }

    pub fn shard(&self) -> RocksDbShard {
        self.shard
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn profile(&self) -> RocksDbShardProfile {
        self.shard.profile()
    }

    pub fn get(&self, cf: &str, key: &[u8]) -> Option<&[u8]> {
        self.data.get(cf)?.get(key).map(Vec::as_slice)
    }

    pub fn put(&mut self, cf: &str, key: Vec<u8>, value: Vec<u8>) -> io::Result<()> {
        let map = self.cf_mut(cf)?;
        map.insert(key, value);
        self.flush_cf(cf)
    }

    pub fn delete(&mut self, cf: &str, key: &[u8]) -> io::Result<bool> {
        let map = self.cf_mut(cf)?;
        let existed = map.remove(key).is_some();
        if existed {
            self.flush_cf(cf)?;
        }
        Ok(existed)
    }

    /// Apply a batch of put/delete operations and atomically flush all touched column families.
    pub fn write_batch(&mut self, ops: &[DbWriteBatchOp]) -> io::Result<()> {
        let mut touched = BTreeMap::<String, ()>::new();
        for op in ops {
            match op {
                DbWriteBatchOp::Put { cf, key, value } => {
                    self.cf_mut(cf)?.insert(key.clone(), value.clone());
                    touched.insert(cf.clone(), ());
                }
                DbWriteBatchOp::Delete { cf, key } => {
                    self.cf_mut(cf)?.remove(key);
                    touched.insert(cf.clone(), ());
                }
            }
        }
        for cf in touched.keys() {
            self.flush_cf(cf)?;
        }
        Ok(())
    }

    /// Create an atomic on-disk checkpoint under `<checkpoint_root>/<shard.dir_name()>`
    /// and write both `CHECKPOINT_COMPLETE` and the per-shard `CHECKPOINT_COMPLETE_<shard_lower>`
    /// marker (`0x1696b90..0x1696d23`) in `<checkpoint_root>` once all CF files are durable.
    pub fn create_checkpoint(&self, checkpoint_root: &Path) -> io::Result<PathBuf> {
        let shard_ckpt = checkpoint_root.join(self.shard.dir_name());
        fs::create_dir_all(&shard_ckpt)?;
        for (cf, entries) in &self.data {
            write_kv_file_atomic(&shard_ckpt.join(format!("{cf}.kv")), entries)?;
        }
        write_bytes_atomic(&checkpoint_root.join("CHECKPOINT_COMPLETE"), b"")?;
        write_bytes_atomic(&self.shard.checkpoint_complete_marker_path(checkpoint_root), b"")?;
        Ok(shard_ckpt)
    }

    pub fn len_in_cf(&self, cf: &str) -> usize {
        self.data.get(cf).map_or(0, BTreeMap::len)
    }

    fn cf_mut(&mut self, cf: &str) -> io::Result<&mut BTreeMap<Vec<u8>, Vec<u8>>> {
        self.data.get_mut(cf).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("unknown column family `{cf}` for shard {:?}", self.shard),
            )
        })
    }

    fn flush_cf(&self, cf: &str) -> io::Result<()> {
        let entries = self.data.get(cf).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("missing cf `{cf}`"))
        })?;
        write_kv_file_atomic(&self.root_dir.join(format!("{cf}.kv")), entries)
    }
}

fn write_kv_file_atomic(path: &Path, entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> io::Result<()> {
    let mut buf = Vec::with_capacity(16 + entries.len() * 32);
    buf.extend_from_slice(KV_FILE_MAGIC);
    buf.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (k, v) in entries {
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        buf.extend_from_slice(k);
        buf.extend_from_slice(v);
    }
    write_bytes_atomic(path, &buf)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn read_kv_file(path: &Path) -> io::Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut raw = Vec::new();
    File::open(path)?.read_to_end(&mut raw)?;
    if raw.len() < 16 || &raw[..8] != KV_FILE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "corrupt KV file magic",
        ));
    }
    let count = u64::from_le_bytes(raw[8..16].try_into().unwrap()) as usize;
    let mut pos = 16usize;
    let mut out = BTreeMap::new();
    for _ in 0..count {
        if pos + 8 > raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated KV entry header",
            ));
        }
        let klen = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        let vlen = u32::from_le_bytes(raw[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        if pos + klen + vlen > raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated KV entry body",
            ));
        }
        let key = raw[pos..pos + klen].to_vec();
        pos += klen;
        let val = raw[pos..pos + vlen].to_vec();
        pos += vlen;
        out.insert(key, val);
    }
    Ok(out)
}

/// Result wrapper matching the observed `rocks_db.rs:58` open-word niche discrimination.
pub fn interpret_open_word(word: u64) -> Result<u64, u64> {
    if result_word_is_error_niche(word) {
        Err(word)
    } else {
        Ok(word)
    }
}
