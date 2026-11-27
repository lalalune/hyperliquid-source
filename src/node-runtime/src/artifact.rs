//! Indexed node artifact loader and monotonic updater matching node #115
//! `node/src/artifact.rs` (`0x4ec71b0..0x4ec79f7`, `0x4e4cbb0..0x4e4d69b`).

use crate::error::NodeError;

/// Observed artifact directory/name in `.rodata 0x9188e2`.
pub const NODE_ARTIFACT_DIR: &str = "node-artifact-2";
pub const NODE_METADATA_FILENAME: &str = "node_metadata.json";
pub const VISOR_METADATA_FILENAME: &str = "visor_metadata.json";

/// Observed updater poll interval at `.rodata 0x4593d0` (`f64 = 5.0` seconds).
pub const ARTIFACT_POLL_INTERVAL_SECS: f64 = 5.0;

/// Observed error message at `.rodata 0x434625` when remote artifact index fails to advance.
pub const INDEX_DID_NOT_INCREASE_MSG: &str = "download index did not increase";

/// Content variants observed in `.rodata 0x46593e..0x465988` (`IndexedArtifactContentSerde` at `0x465a39`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexedArtifactContent {
    NodeMetadata(String),
    VisorMetadata(String),
    HotfixMetadata(String),
    NodeArtifact(Vec<u8>),
    PublisherBinaryMetadata(String),
}

/// 2-element indexed artifact wrapper (`struct IndexedArtifactSerde with 2 elements`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedArtifact {
    pub index: u64,
    pub content: IndexedArtifactContent,
}

impl IndexedArtifact {
    /// Canonical JSON path format `<dir>/<index>.json` observed at `.rodata 0x439f04`.
    pub fn json_path(&self, dir: &str) -> String {
        format!("{dir}/{}.json", self.index)
    }
}

/// Monotonic artifact update tracker enforcing `node/src/artifact.rs` index progression.
#[derive(Clone, Debug)]
pub struct ArtifactUpdater {
    current: IndexedArtifact,
}

impl ArtifactUpdater {
    pub fn new(initial: IndexedArtifact) -> Self {
        Self { current: initial }
    }

    pub fn current(&self) -> &IndexedArtifact {
        &self.current
    }

    pub fn current_index(&self) -> u64 {
        self.current.index
    }

    /// Apply a newly downloaded artifact only if its index strictly increases.
    pub fn apply_update(&mut self, next: IndexedArtifact) -> Result<(), NodeError> {
        if next.index <= self.current.index {
            return Err(NodeError::Config(format!(
                "{INDEX_DID_NOT_INCREASE_MSG}: current={} next={}",
                self.current.index, next.index
            )));
        }
        self.current = next;
        Ok(())
    }
}
