//! Node #115 `l1/src/abci/state.rs` checkpoint restore, loader handoff, freeze-height
//! invariant, and block-state progression.
//!
//! Binary anchors (`RE-009-node115-abci-crate-map`, `RE-009-node115-db-hub-routing-and-abci-schema`):
//! - `0x3c12800..0x3c12af5` (`state.rs:76..82`): persisted height verification `[S+0x28]`
//! - `0x3c13520..0x3c13609` (`state.rs:123:37`): loader handoff tag `1` (`0x3c1353b`)
//! - `0x26a2c80..0x26a326e` (`state.rs:151`): `/dev/null` skip + `.rmp` vs pretty-JSON serialization
//! - `0x22ed1f0..0x22ed70a` (`state.rs:201`): `assertion failed: freeze_height >= self.locus.context.height()`
//! - `0x22ec9b0..0x22ed1ec` (`state.rs:460`): action success status `0x1a2` (`0x22ec9c9`)

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use crate::lt_hash::{LT_HASH_BYTES, LtHash, LtHashes};

pub use node115_abci_checkpoint_replay_fixture::{
    ReplayInitializer, RestoreError, RestoredState, restore_checkpoint,
};

/// Action execution success code checked at `0x22ec9c9` (`state.rs:460`).
pub const ACTION_SUCCESS_CODE: u16 = 0x1a2;

/// Loader handoff tag checked at `0x3c1353b` (`state.rs:123:37`).
pub const LOADER_HANDOFF_TAG: u64 = 1;

/// No-op checkpoint sink path checked at `0x26a2ce4` (`0x6c756e2f7665642f` + `'l'`).
pub const CHECKPOINT_DEV_NULL_PATH: &str = "/dev/null";

/// Extension selecting MessagePack serialization at `0x26a2da4` (`.rodata 0x4659e5`).
pub const CHECKPOINT_RMP_EXTENSION: &str = "rmp";

/// Initial `Vec<u8>` capacity for pretty-JSON fallback at `0x26a2e1b` (`mov edi, 0x80`).
pub const CHECKPOINT_JSON_INITIAL_CAPACITY: usize = 0x80;

/// Two-space pretty-JSON indentation literal at `0x26a2e4b` (`.rodata 0x5f3cc0`).
pub const CHECKPOINT_JSON_INDENT: &str = "  ";

/// Buffered ABCI state serialization capacity proven at `0x26a2881` (`state.rs:193/195`)
/// and `0x4e4b8c1` (`state.rs:161`): `0x1000400` (`16 MiB + 1 KiB = 16,778,240` bytes).
pub const STATE_SERIALIZE_BUF_CAPACITY: usize = 0x100_0400;

/// Nanoseconds-per-second divisor proven at `0x26a2979` (`.rodata 0x458d50` = `1e9_f64`).
pub const ELAPSED_NANOS_PER_SEC: f64 = 1_000_000_000.0;

/// Convert elapsed wall-clock nanoseconds to finite seconds matching `0x26a2979..0x26a2985`:
/// divides by `1e9` (`0x458d50`) and rejects non-finite (`>= f64::INFINITY` at `0x459010`).
pub fn elapsed_secs_from_nanos(elapsed_nanos: f64) -> Option<f64> {
    if !elapsed_nanos.is_finite() || elapsed_nanos < 0.0 {
        return None;
    }
    let secs = elapsed_nanos / ELAPSED_NANOS_PER_SEC;
    if secs.is_finite() { Some(secs) } else { None }
}

/// Error returned when zipped action/result slice lengths differ (`state.rs:340:21`,
/// `0x229b760` / `0x5618890` / `0x5618990`: `cmp rsi, rcx; jne assert_failed`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZipLengthMismatchError {
    pub left_len: usize,
    pub right_len: usize,
}

/// Checked zip enforcing exact `left.len() == right.len()` matching `l1/src/abci/state.rs:340:21`.
pub fn zip_exact_slices<'a, A, B>(
    left: &'a [A],
    right: &'a [B],
) -> Result<Vec<(&'a A, &'a B)>, ZipLengthMismatchError> {
    if left.len() != right.len() {
        return Err(ZipLengthMismatchError {
            left_len: left.len(),
            right_len: right.len(),
        });
    }
    Ok(left.iter().zip(right.iter()).collect())
}

/// Required feature-version byte checked at `0x5a04f52` (`cmp byte ptr [S + 0xb9a], 3`,
/// `"assertion failed: features_ok"` at `0x93a641`).
pub const REQUIRED_FEATURE_VERSION: u8 = 3;

/// Ordered pre-execution guard errors proven in `AbciEngine::apply_block` (`0x5a04ec3..0x5a04f59`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyBlockPreconditionError {
    /// `[S + 0x10e8] == Some(hf)` with `hf < [S + 0x28]` (`0x5a04ede -> 0x5a062d4`).
    HardforkHeightBelowCurrent {
        hardfork_height: u64,
        current_height: u64,
    },
    /// `[S + 0x10e8] == Some(hf)` with `hf == [S + 0x28]` (`0x5a04ee4 -> 0x5a06235`: `!self.state.is_frozen()`).
    StateFrozen { height: u64 },
    /// `round <= parent_round` (`0x5a04eea..0x5a04eed -> 0x5a0621d`: `round > parent_round`).
    NonAdvancingRound { parent_round: u64, round: u64 },
    /// `[S + 0x30] != parent_round` (`0x5a04ef3..0x5a04eff -> 0x5a0624a`).
    ParentRoundMismatch {
        state_round: u64,
        block_parent_round: u64,
    },
    /// 128-bit `[S + 0x18..+0x28] != block_parent_time` (`0x5a04f05..0x5a04f23 -> 0x5a0626d`).
    ParentTimeMismatch {
        state_time: (u64, u64),
        block_parent_time: (u64, u64),
    },
    /// Header action count `!=` payload action count (`0x5a04f29..0x5a04f4c -> 0x5a06290`).
    ActionCountMismatch {
        header_actions: u64,
        payload_actions: u64,
    },
    /// `[S + 0xb9a] != REQUIRED_FEATURE_VERSION` (`0x5a04f52..0x5a04f59 -> 0x5a062b6`: `features_ok`).
    FeatureVersionMismatch { expected: u8, actual: u8 },
}

/// Checkpoint serialization dispatch proven in `l1/src/abci/state.rs:151` (`0x26a2c80..0x26a326e`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointFormat {
    SkipDevNull,
    MessagePackRmp,
    PrettyJson,
}

/// Classify a checkpoint output path identically to `0x26a2cda..0x26a2db7`:
/// - exactly the raw spelling `"/dev/null"` -> `SkipDevNull`
/// - extension == `"rmp"` -> `MessagePackRmp`
/// - everything else (including `".."` or missing/other extension) -> `PrettyJson`
pub fn classify_checkpoint_path(path: &Path) -> CheckpointFormat {
    if path.as_os_str() == CHECKPOINT_DEV_NULL_PATH {
        return CheckpointFormat::SkipDevNull;
    }
    if path.extension().and_then(|e| e.to_str()) == Some(CHECKPOINT_RMP_EXTENSION) {
        CheckpointFormat::MessagePackRmp
    } else {
        CheckpointFormat::PrettyJson
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreezeHeightError {
    FreezeHeightBelowCurrent {
        freeze_height: u64,
        current_height: u64,
    },
}

/// Hardfork version mismatch error proven in `0x595aff0..0x595b1a0` (`.rodata 0x431d7a`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardforkVersionError {
    pub state_version: u64,
    pub expected_version: u64,
}

/// Enforces `state_version == expected_version` matching `0x595b0fa..0x595b146`:
/// `"unexpected state hardfork version: {state}, expected hardfork version: {expected}"`.
pub fn validate_hardfork_version(
    state_version: u64,
    expected_version: u64,
) -> Result<(), HardforkVersionError> {
    if state_version != expected_version {
        return Err(HardforkVersionError {
            state_version,
            expected_version,
        });
    }
    Ok(())
}

/// Snapshot-load hardfork compatibility error proven in `0x15a20a0..0x15a37fe`
/// (`0x15a2219..0x15a221d` and `0x15a2ae9..0x15a2aed`: `cmp [r15+0x10], rax; ja`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateHardforkNewerError {
    pub state_version: u64,
    pub binary_version: u64,
}

impl fmt::Display for StateHardforkNewerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "state hardfork version {} is newer than binary hardfork version {}",
            self.state_version, self.binary_version
        )
    }
}

/// Enforces `state_version <= binary_version` matching `0x15a2219`/`0x15a2ae9` (`ja` rejects
/// snapshots produced by a newer hardfork while allowing equal or older upgradeable snapshots).
pub const fn validate_state_hardfork_not_newer(
    state_version: u64,
    binary_version: u64,
) -> Result<(), StateHardforkNewerError> {
    if state_version > binary_version {
        Err(StateHardforkNewerError {
            state_version,
            binary_version,
        })
    } else {
        Ok(())
    }
}

/// Self-contained persistent ABCI checkpoint bundle stored under `<db_home>/checkpoint/<height>/`
/// containing state metadata (`abci_state_meta.json`), `lt_hashes.json`, and `CHECKPOINT_COMPLETE`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciCheckpointBundle {
    pub height: u64,
    pub round: u64,
    pub hardfork_version: u64,
    pub hardfork_height: Option<u64>,
    pub lt_hashes: LtHashes,
}

#[derive(Debug)]
pub enum CheckpointBundleError {
    Io(io::Error),
    MissingCompleteMarker,
    CorruptPayload(&'static str),
    StateHardforkNewer(StateHardforkNewerError),
}

impl From<io::Error> for CheckpointBundleError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl AbciCheckpointBundle {
    /// Atomically persist metadata + `lt_hashes.json` + `CHECKPOINT_COMPLETE` into `checkpoint_dir`.
    pub fn save_to_checkpoint_dir(&self, checkpoint_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(checkpoint_dir)?;
        let hf_height_json = match self.hardfork_height {
            Some(h) => h.to_string(),
            None => "null".to_string(),
        };
        let meta = format!(
            "{{\"height\":{},\"round\":{},\"hardfork_version\":{},\"hardfork_height\":{}}}\n",
            self.height, self.round, self.hardfork_version, hf_height_json
        );
        write_atomic(
            &checkpoint_dir.join("abci_state_meta.json"),
            meta.as_bytes(),
        )?;
        let lt_json = format!(
            "{{\"accounts_hash\":{},\"contracts_hash\":{},\"storage_hash\":{}}}\n",
            encode_lt_hash_json(&self.lt_hashes.accounts_hash),
            encode_lt_hash_json(&self.lt_hashes.contracts_hash),
            encode_lt_hash_json(&self.lt_hashes.storage_hash),
        );
        write_atomic(&checkpoint_dir.join("lt_hashes.json"), lt_json.as_bytes())?;
        write_atomic(&checkpoint_dir.join("CHECKPOINT_COMPLETE"), b"")?;
        Ok(())
    }

    /// Load and validate a checkpoint bundle, enforcing `CHECKPOINT_COMPLETE` and
    /// `validate_state_hardfork_not_newer(state.hardfork_version, binary_hardfork_version)`.
    pub fn load_from_checkpoint_dir(
        checkpoint_dir: &Path,
        binary_hardfork_version: u64,
    ) -> Result<Self, CheckpointBundleError> {
        if !checkpoint_dir.join("CHECKPOINT_COMPLETE").is_file() {
            return Err(CheckpointBundleError::MissingCompleteMarker);
        }
        let meta_str = fs::read_to_string(checkpoint_dir.join("abci_state_meta.json"))?;
        let height = extract_u64_field(&meta_str, "\"height\":")
            .ok_or(CheckpointBundleError::CorruptPayload("height"))?;
        let round = extract_u64_field(&meta_str, "\"round\":")
            .ok_or(CheckpointBundleError::CorruptPayload("round"))?;
        let hardfork_version = extract_u64_field(&meta_str, "\"hardfork_version\":")
            .ok_or(CheckpointBundleError::CorruptPayload("hardfork_version"))?;
        validate_state_hardfork_not_newer(hardfork_version, binary_hardfork_version)
            .map_err(CheckpointBundleError::StateHardforkNewer)?;
        let hardfork_height = extract_opt_u64_field(&meta_str, "\"hardfork_height\":")
            .ok_or(CheckpointBundleError::CorruptPayload("hardfork_height"))?;

        let lt_str = fs::read_to_string(checkpoint_dir.join("lt_hashes.json"))?;
        let accounts_hash = parse_lt_hash_section(&lt_str, "\"accounts_hash\":")
            .ok_or(CheckpointBundleError::CorruptPayload("accounts_hash"))?;
        let contracts_hash = parse_lt_hash_section(&lt_str, "\"contracts_hash\":")
            .ok_or(CheckpointBundleError::CorruptPayload("contracts_hash"))?;
        let storage_hash = parse_lt_hash_section(&lt_str, "\"storage_hash\":")
            .ok_or(CheckpointBundleError::CorruptPayload("storage_hash"))?;

        Ok(Self {
            height,
            round,
            hardfork_version,
            hardfork_height,
            lt_hashes: LtHashes {
                accounts_hash,
                contracts_hash,
                storage_hash,
            },
        })
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

fn encode_lt_hash_json(h: &LtHash) -> String {
    let mut hex = String::with_capacity(LT_HASH_BYTES * 2);
    for &b in &h.hash {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }
    format!(
        "{{\"n_elements\":{},\"n_bytes\":{},\"hash\":\"0x{}\"}}",
        h.n_elements, h.n_bytes, hex
    )
}

fn extract_u64_field(src: &str, key: &str) -> Option<u64> {
    let rest = src.split_once(key)?.1.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse::<u64>().ok()
}

fn extract_opt_u64_field(src: &str, key: &str) -> Option<Option<u64>> {
    let rest = src.split_once(key)?.1.trim_start();
    if rest.starts_with("null") {
        Some(None)
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse::<u64>().ok().map(Some)
    }
}

fn parse_lt_hash_section(src: &str, key: &str) -> Option<LtHash> {
    let rest = src.split_once(key)?.1;
    let obj_end = rest.find('}')?;
    let obj = &rest[..=obj_end];
    let n_elements = extract_u64_field(obj, "\"n_elements\":")?;
    let n_bytes = extract_u64_field(obj, "\"n_bytes\":")?;
    let hex_rest = obj.split_once("\"hash\":\"0x")?.1;
    let hex_end = hex_rest.find('"')?;
    let hex_str = &hex_rest[..hex_end];
    if hex_str.len() != LT_HASH_BYTES * 2 {
        return None;
    }
    let mut hash = [0u8; LT_HASH_BYTES];
    let bytes = hex_str.as_bytes();
    for (i, slot) in hash.iter_mut().enumerate() {
        let hi = decode_hex_nibble(bytes[i * 2])?;
        let lo = decode_hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(LtHash {
        hash,
        n_elements,
        n_bytes,
    })
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Enforces the `l1/src/abci/state.rs:201` invariant (`0x22ed1f0`):
/// `freeze_height >= current_height`.
pub fn validate_freeze_height(
    freeze_height: u64,
    current_height: u64,
) -> Result<(), FreezeHeightError> {
    if freeze_height < current_height {
        return Err(FreezeHeightError::FreezeHeightBelowCurrent {
            freeze_height,
            current_height,
        });
    }
    Ok(())
}

/// Checked wrapper around `RestoredState` supporting saturating height advance (`0x54838d3..0x54838f1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbciState {
    pub inner: RestoredState,
    pub hardfork_height: Option<u64>,
    pub periodic_root_cadence: u64,
}

impl AbciState {
    pub fn new(
        restored: RestoredState,
        periodic_root_cadence: u64,
        hardfork_height: Option<u64>,
    ) -> Self {
        Self {
            inner: restored,
            hardfork_height,
            periodic_root_cadence,
        }
    }

    pub fn height(&self) -> u64 {
        self.inner.height
    }

    pub fn round(&self) -> u64 {
        self.inner.round
    }

    /// Advance `[S + 0x28]` with saturation (`0x54838d3..0x54838e5`) and store new round `[S + 0x30]`.
    pub fn advance_block(&mut self, new_round: u64) {
        self.inner.height = self.inner.height.saturating_add(1);
        self.inner.round = new_round;
    }

    pub fn check_freeze_height(&self, freeze_height: u64) -> Result<(), FreezeHeightError> {
        validate_freeze_height(freeze_height, self.inner.height)
    }

    /// Exact `self.state.is_frozen()` predicate proven at `0x5a04ec3..0x5a04ee4`:
    /// frozen when `hardfork_height == Some(current_height)`.
    pub fn is_frozen(&self) -> bool {
        self.hardfork_height == Some(self.inner.height)
    }

    /// Evaluates all 6 ordered pre-execution guards proven at `0x5a04ec3..0x5a04f59`.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_apply_preconditions(
        &self,
        parent_round: u64,
        round: u64,
        state_time: (u64, u64),
        block_parent_time: (u64, u64),
        header_actions: u64,
        payload_actions: u64,
        feature_version: u8,
    ) -> Result<(), ApplyBlockPreconditionError> {
        if let Some(hf) = self.hardfork_height {
            if hf < self.inner.height {
                return Err(ApplyBlockPreconditionError::HardforkHeightBelowCurrent {
                    hardfork_height: hf,
                    current_height: self.inner.height,
                });
            }
            if hf == self.inner.height {
                return Err(ApplyBlockPreconditionError::StateFrozen {
                    height: self.inner.height,
                });
            }
        }
        if round <= parent_round {
            return Err(ApplyBlockPreconditionError::NonAdvancingRound {
                parent_round,
                round,
            });
        }
        if self.inner.round != parent_round {
            return Err(ApplyBlockPreconditionError::ParentRoundMismatch {
                state_round: self.inner.round,
                block_parent_round: parent_round,
            });
        }
        if state_time != block_parent_time {
            return Err(ApplyBlockPreconditionError::ParentTimeMismatch {
                state_time,
                block_parent_time,
            });
        }
        if header_actions != payload_actions {
            return Err(ApplyBlockPreconditionError::ActionCountMismatch {
                header_actions,
                payload_actions,
            });
        }
        if feature_version != REQUIRED_FEATURE_VERSION {
            return Err(ApplyBlockPreconditionError::FeatureVersionMismatch {
                expected: REQUIRED_FEATURE_VERSION,
                actual: feature_version,
            });
        }
        Ok(())
    }
}
