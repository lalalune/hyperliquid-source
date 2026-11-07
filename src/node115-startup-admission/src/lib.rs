//! Offline path admission at the node #115 startup enumerator boundary.
//!
//! The caller supplies enumeration and metadata outcomes and already-joined
//! path bytes. This module never opens a directory or reads metadata. It returns
//! paths in encounter order, before the native sort/container construction;
//! it does not select a checkpoint or reproduce the native error ABI.

/// The two views selected by the startup caller's enumerator wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// First wrapper, `0x1501290`: retain the mapper's directory flag.
    Directories,
    /// Nested wrapper, `0x15021d0`: retain the mapper's false directory flag.
    /// This includes metadata failures, not only regular files.
    NonDirectories,
}

/// Interpreted result of the metadata helper, supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metadata {
    /// The mapper observes metadata result tag 2 and produces flag false.
    Failed,
    /// Mode word from a valid successful native metadata result.
    Mode(u32),
}

/// One supplied enumeration outcome. Path joining is outside this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry<'a> {
    /// The per-entry enumeration error is suppressed by the mapper.
    Failed,
    Path {
        joined_path_bytes: &'a [u8],
        metadata: Metadata,
    },
}

/// Admit already-enumerated paths for one wrapper's view.
///
/// `Err(E)` represents an already-translated directory-open failure. Its
/// representation and native conversion helper are opaque to this API. After
/// opening succeeds, per-entry errors and invalid UTF-8 paths are skipped;
/// metadata failure gives a false directory flag. The returned `Vec` preserves
/// supplied order and duplicates intentionally: native ordering, deduplication,
/// container construction, and later checkpoint selection remain outside scope.
pub fn admit_listing<E>(view: View, listing: Result<&[Entry<'_>], E>) -> Result<Vec<String>, E> {
    let entries = listing?;
    let mut admitted = Vec::new();
    for entry in entries {
        let Entry::Path {
            joined_path_bytes,
            metadata,
        } = entry
        else {
            continue;
        };
        let is_directory = match metadata {
            Metadata::Failed => false,
            Metadata::Mode(mode) => mode & 0xf000 == 0x4000,
        };
        let Ok(path) = std::str::from_utf8(joined_path_bytes) else {
            continue;
        };
        let keep = match view {
            View::Directories => is_directory,
            View::NonDirectories => !is_directory,
        };
        if keep {
            admitted.push(path.to_owned());
        }
    }
    Ok(admitted)
}
