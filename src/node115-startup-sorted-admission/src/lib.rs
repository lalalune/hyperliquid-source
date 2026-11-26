use node115_startup_admission::{Entry, View, admit_listing};

/// Admit the supplied listing and sort the resulting owned paths by their
/// UTF-8 bytes. Equal paths retain encounter order. The supplied already-joined
/// bytes follow `admit_listing`'s input premise; native path construction is
/// not modeled. This models the selected collector's logical sort result, not
/// native scratch allocation, tree construction, or checkpoint selection.
pub fn admit_sorted_listing<E>(
    view: View,
    listing: Result<&[Entry<'_>], E>,
) -> Result<Vec<String>, E> {
    let mut admitted = admit_listing(view, listing)?;
    admitted.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(admitted)
}
