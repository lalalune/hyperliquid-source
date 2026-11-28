//! Node #115 `db/src/db_home.rs` path validation, checkpoint discovery,
//! lifecycle planning, restore copy command preparation, and replica end-height reader.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`):
//! - `0x44699c0..0x4469bd8` & `0x5a007c0..0x5a00af9` (`db_home.rs:85:13`):
//!   `"EvmState"` & `"db_home contains db_bundle in path: "` validation.
//! - `0x25d3f20..0x25d4cab`, `0x4468e30..0x44699c0`, `0x59ffa30..0x5a007bb` (`db_home.rs:21:24`):
//!   checkpoint directory discovery (`node115-checkpoint-discovery`).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use node115_checkpoint_discovery::{Candidate as CheckpointCandidate, candidates, find_checkpoint};
pub use node115_checkpoint_plan::{CheckpointMode, CheckpointPlan, plan as checkpoint_plan};
pub use node115_replica_end_height::{
    Error as ReplicaHeightError, directory_end_height, latest_end_height,
};
pub use node115_restore_copy::prepare_first_copy;

/// Subdirectory name checked at `0x4469a72` (`rodata 0x459a58`) and `node115-restore-copy`.
pub const EVM_STATE_SUBDIR: &str = "EvmState";

/// Checkpoint container subdirectory formatted at `0x44683a8` (`db_home.rs:286..317`, rodata `0x434739`).
pub const CHECKPOINT_SUBDIR: &str = "checkpoint";

/// LT-hashes companion metadata filename formatted at `0x446857f` / `0x44685d9` (rodata `0x44f3c9`).
pub const LT_HASHES_FILENAME: &str = "lt_hashes.json";

/// Exact 74 contiguous `Exchange` struct field offsets captured into `[rsp+0x128..=rsp+0x370]`
/// for ABCI state-root hashing in both live (`0x269a1b0`) and slow (`0x4e34ce0`) node #115 engines.
pub const EXCHANGE_ROOT_CAPTURE_OFFSETS: [u16; 74] = [
    0x0000, 0x07c0, 0x0080, 0x07d8, 0x0968, 0x0b9a, 0x0b98, 0x09f8,
    0x0670, 0x0b78, 0x0a78, 0x09b0, 0x0a18, 0x0b99, 0x0b90, 0x0a38,
    0x3ac0, 0x3ad8, 0x3af0, 0x4158, 0x4168, 0x3c58, 0x41e8, 0x0ba0,
    0x3f08, 0x0d88, 0x4200, 0x4220, 0x10e8, 0x4178, 0x4288, 0x4294,
    0x4228, 0x3ce8, 0x3f88, 0x4188, 0x3fa8, 0x3fc8, 0x42ac, 0x4230,
    0x4238, 0x10f8, 0x4240, 0x3a00, 0x3a40, 0x3a80, 0x1108, 0x3d40,
    0x4198, 0x3ff8, 0x4018, 0x4038, 0x37e0, 0x42ad, 0x4058, 0x40a0,
    0x40c0, 0x41a8, 0x41d8, 0x4250, 0x42a0, 0x42ae, 0x4268, 0x37f0,
    0x4138, 0x42af, 0x3830, 0x3d78, 0x3858, 0x42b0, 0x4270, 0x3d98,
    0x3e50, 0x3908,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbHomeError {
    ContainsDbBundle { path: PathBuf },
}

/// Validates a `DbHome` path per `db_home.rs:85` (`0x44699c0` / `0x5a007c0`):
/// rejects paths containing `"db_bundle"`.
pub fn validate_db_home_path(path: &Path) -> Result<PathBuf, DbHomeError> {
    let raw = path.as_os_str().as_encoded_bytes();
    if raw.windows(9).any(|w| w == b"db_bundle") {
        return Err(DbHomeError::ContainsDbBundle {
            path: path.to_path_buf(),
        });
    }
    Ok(path.to_path_buf())
}

/// Verified offline handle over a `DbHome` directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbHome {
    root: PathBuf,
}

impl DbHome {
    pub fn new(root: &Path) -> Result<Self, DbHomeError> {
        Ok(Self {
            root: validate_db_home_path(root)?,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn evm_state_dir(&self) -> PathBuf {
        self.root.join(EVM_STATE_SUBDIR)
    }

    pub fn checkpoint_subdir(&self) -> PathBuf {
        self.root.join(CHECKPOINT_SUBDIR)
    }

    pub fn checkpoint_dir_for_height(&self, height: u64) -> PathBuf {
        self.checkpoint_subdir().join(height.to_string())
    }

    pub fn lt_hashes_path(&self, height: u64) -> PathBuf {
        self.checkpoint_dir_for_height(height).join(LT_HASHES_FILENAME)
    }

    pub fn discover_checkpoints(&self) -> io::Result<Vec<CheckpointCandidate>> {
        candidates(&self.root)
    }

    pub fn find_checkpoint_at(&self, height: u64) -> Option<CheckpointCandidate> {
        find_checkpoint(&self.root, height)
    }

    pub fn prepare_evm_restore_command(
        &self,
        selected_checkpoint_dir: &Path,
    ) -> io::Result<Command> {
        prepare_first_copy(selected_checkpoint_dir, &self.root)
    }

    /// Exact 3-stage latest-checkpoint loader proven in `db/src/db_home.rs:21:24`
    /// (`0x4468e30`, `0x25d3f20`, `0x59ffa30`):
    /// 1. Verifies `<db_home>/checkpoint` exists (`"checkpoint outer dir does not exist ..."`).
    /// 2. Scans entries strictly matching unsigned ASCII digits (`+`/`-` rejected at `0x4469183`/`0x4469188`),
    ///    returning `"no checkpoints to load: ..."` if none exist.
    /// 3. Sorts descending by height and requires a regular global or EVM completion
    ///    marker plus any supplied `required_subdir`. If none qualify, returns
    ///    `"unable to load any current checkpoint from ..."`.
    pub fn load_latest_checkpoint(
        &self,
        required_subdir: Option<&str>,
    ) -> Result<CheckpointCandidate, LoadLatestCheckpointError> {
        self.load_latest_checkpoint_where(|path| {
            required_subdir.is_none_or(|subdir| path.join(subdir).exists())
        })
    }

    /// Select the newest completed checkpoint containing a regular payload file.
    pub fn load_latest_checkpoint_with_payload_file(
        &self,
        filename: &str,
    ) -> Result<CheckpointCandidate, LoadLatestCheckpointError> {
        self.load_latest_checkpoint_where(|path| path.join(filename).is_file())
    }

    fn load_latest_checkpoint_where(
        &self,
        has_payload: impl Fn(&Path) -> bool,
    ) -> Result<CheckpointCandidate, LoadLatestCheckpointError> {
        let outer = self.checkpoint_subdir();
        if !outer.is_dir() {
            return Err(LoadLatestCheckpointError::OuterDirDoesNotExist { dir: outer });
        }
        let mut parsed = Vec::new();
        for entry in fs::read_dir(&outer).map_err(LoadLatestCheckpointError::Io)? {
            let entry = entry.map_err(LoadLatestCheckpointError::Io)?;
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            // Matches `0x4469183` ('+'), `0x4469188` ('-'), and `0x44691d7` (ASCII digits only)
            if name_str.is_empty() || !name_str.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(height) = name_str.parse::<u64>() {
                parsed.push((height, entry.path()));
            }
        }
        if parsed.is_empty() {
            return Err(LoadLatestCheckpointError::NoCheckpointsToLoad { dir: outer });
        }
        parsed.sort_by_key(|b| std::cmp::Reverse(b.0));
        for (height, path) in parsed {
            if !path.join("CHECKPOINT_COMPLETE").is_file()
                && !path.join("CHECKPOINT_COMPLETE_EVMSTATE").is_file()
            {
                continue;
            }
            if !has_payload(&path) {
                continue;
            }
            return Ok(CheckpointCandidate { height, path });
        }
        Err(LoadLatestCheckpointError::UnableToLoadAnyCurrentCheckpoint { dir: outer })
    }
}

/// Exact 3-variant checkpoint load error ladder proven in `db/src/db_home.rs:21:24` (`0x4468e30`).
#[derive(Debug)]
pub enum LoadLatestCheckpointError {
    OuterDirDoesNotExist { dir: PathBuf },
    NoCheckpointsToLoad { dir: PathBuf },
    UnableToLoadAnyCurrentCheckpoint { dir: PathBuf },
    Io(io::Error),
}

impl fmt::Display for LoadLatestCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OuterDirDoesNotExist { dir } => {
                write!(f, "checkpoint outer dir does not exist {}", dir.display())
            }
            Self::NoCheckpointsToLoad { dir } => {
                write!(f, "no checkpoints to load: {}", dir.display())
            }
            Self::UnableToLoadAnyCurrentCheckpoint { dir } => {
                write!(
                    f,
                    "unable to load any current checkpoint from {}",
                    dir.display()
                )
            }
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}
