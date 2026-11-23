//! Read-only projection of the node 115 EVM checkpoint archive planner on Unix.

use node115_startup_admission::{admit_listing, Entry, Metadata, View};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub struct ArchivePlan {
    pub temporary_path: String,
    pub destination_path: String,
    pub members: Vec<String>,
}

fn status_names(directory: &Path) -> io::Result<BTreeSet<String>> {
    if !directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "periodic_abci_state_status_base_dir does not exist: {}",
                directory.display()
            ),
        ));
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(directory)?.filter_map(Result::ok) {
        let path = entry.path();
        let metadata = fs::metadata(&path)
            .map(|m| Metadata::Mode(m.mode()))
            .unwrap_or(Metadata::Failed);
        let row = Entry::Path {
            joined_path_bytes: path.as_os_str().as_bytes(),
            metadata,
        };
        for admitted in admit_listing(View::NonDirectories, Ok::<_, io::Error>(&[row]))? {
            // A read_dir entry always has a normal final component.
            if let Some(name) = Path::new(&admitted).file_name().and_then(|s| s.to_str()) {
                names.insert(name.to_owned());
            }
        }
    }
    Ok(names)
}

/// Supply the root and date as already displayed by the node, checkpoint
/// heights in native post-sort order, and the third temporary-name argument.
/// Reads the status directory and checks the destination. Creates no files.
pub fn plan_archive(
    root: &str,
    date: &str,
    ordered_checkpoint_heights: &[u64],
    temporary_id: impl FnOnce() -> u64,
) -> io::Result<Option<ArchivePlan>> {
    let directory = format!("{root}/data/periodic_abci_state_statuses/{date}");
    let names = status_names(Path::new(&directory))?;
    let members: Vec<_> = ordered_checkpoint_heights
        .iter()
        .map(u64::to_string)
        .filter(|name| names.contains(name))
        .collect();
    let Some((first, last)) = members.first().zip(members.last()) else {
        return Ok(None);
    };
    let temporary_path = format!(
        "/tmp/evm_state_checkpoints_{first}_{last}_{}.tar",
        temporary_id()
    );
    let destination_path = format!("{root}/data/daily_evm_checkpoints/{date}/{first}_{last}.tar");
    if Path::new(&destination_path).is_file() {
        return Ok(None);
    }
    Ok(Some(ArchivePlan {
        members,
        temporary_path,
        destination_path,
    }))
}
