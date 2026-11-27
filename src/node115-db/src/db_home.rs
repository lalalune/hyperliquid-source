//! Node #115 `db/src/db_home.rs` path validation, checkpoint discovery,
//! lifecycle planning, restore copy command preparation, and replica end-height reader.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`):
//! - `0x44699c0..0x4469bd8` & `0x5a007c0..0x5a00af9` (`db_home.rs:85:13`):
//!   `"EvmState"` & `"db_home contains db_bundle in path: "` validation.
//! - `0x25d3f20..0x25d4cab`, `0x4468e30..0x44699c0`, `0x59ffa30..0x5a007bb` (`db_home.rs:21:24`):
//!   checkpoint directory discovery (`node115-checkpoint-discovery`).

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
}
