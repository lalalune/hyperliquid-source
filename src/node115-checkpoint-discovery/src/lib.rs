//! Read-only projection of the local node 115 checkpoint discovery path.
use node115_startup_admission::{Entry, Metadata, View, admit_listing};
use std::fs;
use std::io;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    pub height: u64,
    pub path: PathBuf,
}

/// Inspect an already-formatted checkpoint directory. Missing or non-directory
/// roots yield no candidates. An error opening a directory remains observable.
pub fn candidates(directory: &Path) -> io::Result<Vec<Candidate>> {
    if !directory.is_dir() {
        return Ok(Vec::new());
    }
    let rows: Vec<_> = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| {
            let path = entry.path();
            let metadata = fs::metadata(&path)
                .map(|m| Metadata::Mode(m.mode()))
                .unwrap_or(Metadata::Failed);
            (path, metadata)
        })
        .collect();
    let entries: Vec<_> = rows
        .iter()
        .map(|(path, metadata)| Entry::Path {
            joined_path_bytes: path.as_os_str().as_bytes(),
            metadata: *metadata,
        })
        .collect();
    let paths = admit_listing(View::Directories, Ok::<_, io::Error>(&entries))?;
    let mut heights: Vec<u64> = paths
        .iter()
        .filter_map(|name| Path::new(name).file_name()?.to_str()?.parse().ok())
        .collect();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    Ok(heights
        .into_iter()
        .filter_map(|height| {
            let path = directory.join(height.to_string());
            (path.join("CHECKPOINT_COMPLETE").is_file()
                || path.join("CHECKPOINT_COMPLETE_EVMSTATE").is_file()
                // Preserve checkpoints accepted by the earlier reconstruction.
                || path.join("CHECKPOINT_COMPLETE_EvmState").is_file())
            .then_some(Candidate { height, path })
        })
        .collect())
}

/// Select the first admitted row matching this height. The native caller
/// also gets the no-candidate sentinel on the ordinary listing-failure path.
pub fn find_checkpoint(directory: &Path, requested: u64) -> Option<Candidate> {
    candidates(directory)
        .ok()?
        .into_iter()
        .find(|row| row.height == requested)
}
