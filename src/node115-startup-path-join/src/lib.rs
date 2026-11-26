//! Selected byte-oriented startup path join, composed with prior admission.
use node115_startup_admission::{Entry, Metadata, View, admit_listing};
use std::ffi::CStr;

/// One enumeration result. `Name` excludes its terminating NUL when joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameEntry<'a> {
    Failed,
    Name(&'a CStr),
}

/// Logical result of the selected successful byte join. This does not model
/// allocation failure, path normalization or filesystem access.
pub fn join_path_bytes(base: &[u8], child: &[u8]) -> Vec<u8> {
    let mut out = if child.first() == Some(&b'/') {
        Vec::new()
    } else {
        base.to_vec()
    };
    if child.first() != Some(&b'/') && !out.is_empty() && out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(child);
    out
}

/// Join each successful native name, query supplied metadata on those exact
/// bytes, then pass the joined result to the existing UTF-8/view admission.
/// The crate performs no filesystem access; `metadata` is supplied by the caller.
/// Allocation behavior is not modeled. A failed entry or outer error invokes no callback.
pub fn admit_named_listing<E, F>(
    view: View,
    base: &[u8],
    listing: Result<&[NameEntry<'_>], E>,
    metadata: &mut F,
) -> Result<Vec<String>, E>
where
    F: FnMut(&[u8]) -> Metadata,
{
    let entries = listing?;
    let mut joined = Vec::new();
    for entry in entries {
        if let NameEntry::Name(name) = entry {
            let bytes = join_path_bytes(base, name.to_bytes());
            let result = metadata(&bytes);
            joined.push((bytes, result));
        }
    }
    let mapped: Vec<_> = joined
        .iter()
        .map(|(bytes, metadata)| Entry::Path {
            joined_path_bytes: bytes,
            metadata: *metadata,
        })
        .collect();
    admit_listing(view, Ok::<_, E>(&mapped))
}
