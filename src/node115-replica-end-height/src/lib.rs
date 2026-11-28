//! Offline replica-directory ending-height reader for node 115.
use node115_reverse_path_components::{Component, Reverse};
use node115_startup_admission::{Entry, Metadata, View, admit_listing};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NoDateDirectory,
    NoUncompressedFile,
    Filename(std::num::ParseIntError),
    NoEndHeights,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn paths(directory: &Path, view: View) -> io::Result<BTreeSet<String>> {
    let listing = fs::read_dir(directory)?
        .map(|entry| {
            entry.ok().map(|entry| {
                let path = entry.path();
                let metadata = fs::metadata(&path)
                    .map(|metadata| Metadata::Mode(metadata.mode()))
                    .unwrap_or(Metadata::Failed);
                (path, metadata)
            })
        })
        .collect::<Vec<_>>();
    let entries = listing
        .iter()
        .map(|entry| match entry {
            Some((path, metadata)) => Entry::Path {
                joined_path_bytes: path.as_os_str().as_bytes(),
                metadata: *metadata,
            },
            None => Entry::Failed,
        })
        .collect::<Vec<_>>();
    Ok(admit_listing(view, Ok::<_, io::Error>(&entries))?
        .into_iter()
        .collect())
}

fn newline_count(path: &str) -> io::Result<u64> {
    let mut file = File::open(path)?;
    let mut count = 0u64;
    let mut buffer = [0; 8192];
    loop {
        let n = match file.read(&mut buffer) {
            Ok(0) => return Ok(count),
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        count += buffer[..n].iter().filter(|&&byte| byte == b'\n').count() as u64;
    }
}

/// Reads the selected date directory and latest eligible file in a single
/// replica directory. The start height is the decimal filename. The line
/// count is the number of LF bytes, including empty lines.
pub fn directory_end_height(directory: &Path) -> Result<u64, Error> {
    let date = paths(directory, View::Directories)?
        .pop_last()
        .ok_or(Error::NoDateDirectory)?;
    let file = paths(Path::new(&date), View::NonDirectories)?
        .into_iter()
        .rev()
        .find(|path| !path.ends_with(".lz4"))
        .ok_or(Error::NoUncompressedFile)?;
    let parsed = match Reverse::new(file.as_bytes()).next_back() {
        Some(Component::Normal(name)) => std::str::from_utf8(name).unwrap_or(&file),
        _ => &file,
    };
    let start = parsed.parse::<u64>().map_err(Error::Filename)?;
    Ok(start.saturating_add(newline_count(&file)?))
}

/// Fails if the outer directory cannot be opened or none of its newest five
/// directories supplies an ending height. Directory names use bytewise order.
pub fn latest_end_height(root: &Path) -> Result<u64, Error> {
    paths(root, View::Directories)?
        .into_iter()
        .rev()
        .take(5)
        .filter_map(|dir| directory_end_height(Path::new(&dir)).ok())
        .max()
        .ok_or(Error::NoEndHeights)
}

/// Selected startup decision after the replica-end-height probe.
#[derive(Debug)]
pub enum StartingHeightCheck {
    /// The mode byte differs from 1, so the replica tree is not read.
    Disabled,
    /// Native startup continues without a height comparison on this branch.
    ReplicaEndUnavailable(Error),
    AtOrAboveReplicaEnd {
        last_applied: u64,
    },
    BelowReplicaEnd {
        last_applied: u64,
    },
}

/// Check the requested starting height on the selected ordinary startup path.
///
/// Supply the local `data/replica_cmds` directory. Probe errors remain observable
/// to the offline caller as a bypass rather than as a successful comparison.
pub fn check_starting_height(
    replica_root: &Path,
    starting_height: u64,
    mode: u8,
) -> StartingHeightCheck {
    if mode != 1 {
        return StartingHeightCheck::Disabled;
    }
    let last_applied = match latest_end_height(replica_root) {
        Ok(height) => height,
        Err(error) => return StartingHeightCheck::ReplicaEndUnavailable(error),
    };
    if starting_height < last_applied {
        StartingHeightCheck::BelowReplicaEnd { last_applied }
    } else {
        StartingHeightCheck::AtOrAboveReplicaEnd { last_applied }
    }
}
