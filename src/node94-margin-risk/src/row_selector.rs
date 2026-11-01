//! Qualified posthash numeric relation from the node94 row selector.
//!
//! This module returns owned numeric choices; it is not the native pointer ABI.
//! Its checked entry adds explicitly chosen input-refusal and loop-bound policy.
//! Pre-source freeze SHA-256:
//! 515b7a3abcbb4dab494632d381d1a9377d3ea4120a7090702c96ccebf9269f77
//!
//! The native scope is ELF VA [0x36f57f0, 0x36f5948), node #94 SHA-256
//! 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
//! Only bucket/default selection and the initializer-needed predicate are
//! modeled. There is no row reference, constructor, generic Once call, hash
//! implementation, allocation, lifetime reconstruction or economic field here.

#![forbid(unsafe_code)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("The qualified node94 selector requires 64-bit usize.");

/// A numeric choice only; this enum is not the target's return-pointer ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowChoice {
    Bucket(usize),
    SharedDefault,
}

/// No row or reference escapes through this result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualifiedRowSelection {
    pub choice: RowChoice,
    /// Whether the u32 at the native post-search load is nonzero; no Once model.
    pub initializer_needed: bool,
}

/// New safe-API refusals; these variants are not recovered native errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorInputError {
    /// A nonempty view needs a power-of-two control length of at least 16.
    ControlShape,
    /// There must be one readable 20-byte key slot per logical control byte.
    KeyCoverage,
    /// One complete group cycle found neither a matching key nor an empty byte.
    NoNormalExit,
}

/// Checked entry to the qualified conditional posthash numeric relation.
///
/// Normal-correspondence premises for a nonzero `entry_count` (shape and key
/// coverage are also checked by this API):
/// - `controls.len()` is a power of two and at least 16; `keys` covers it.
///   The native mask loaded from map+8 equals `controls.len() - 1`.
/// - `keys[i]` supplies exactly the first 20 bytes of native entry
///   `C - (i + 1) * 120`. Its four padding bytes and 96 value bytes are absent.
/// - For capacity N, native control byte at C+j equals `controls[j & (N-1)]`
///   for 0 <= j < N+15, including the 15-byte mirror after the logical array.
///   This is a numeric view of stable valid groups, not their physical layout.
/// - `supplied_hash` represents H at the native hash-return boundary. Lifting
///   this relation to a whole lookup also requires H to be the actual native
///   hash of `query` for that view; synthetic fixed-H states do not prove that.
/// - A normal hit or empty group terminates the probe; producer invariants and
///   malformed-input behavior are outside this qualified relation.
///
/// All input slices are immutable for this call. The result makes no promise
/// about native row lifetime, aliasing, initialization success or later mutation.
/// `observed_state` is the word read at 0x36f58df (searched path) or 0x36f5901
/// (zero-count path), after selection. An entry-time snapshot may be used only
/// under an explicit stability premise extending through that native load.
/// For zero `entry_count`, no control or key element is inspected.
///
/// Shape/key refusals and termination after one complete group cycle are new
/// API policy. They do not predict native faults or nontermination. A normal
/// native hit/empty must occur within this cycle: triangular offsets permute
/// the N/16 groups when N is a power of two.
pub fn select_row_after_hash(
    entry_count: u64,
    supplied_hash: u64,
    controls: &[u8],
    keys: &[[u8; 20]],
    query: &[u8; 20],
    observed_state: u32,
) -> Result<QualifiedRowSelection, SelectorInputError> {
    if entry_count != 0 {
        if controls.len() < 16 || !controls.len().is_power_of_two() {
            return Err(SelectorInputError::ControlShape);
        }
        if keys.len() < controls.len() {
            return Err(SelectorInputError::KeyCoverage);
        }
    }
    select_row_qualified(
        entry_count,
        supplied_hash,
        controls,
        keys,
        query,
        observed_state,
    )
}

fn select_row_qualified(
    entry_count: u64,
    supplied_hash: u64,
    controls: &[u8],
    keys: &[[u8; 20]],
    query: &[u8; 20],
    observed_state: u32,
) -> Result<QualifiedRowSelection, SelectorInputError> {
    let initializer_needed = observed_state != 0;
    if entry_count == 0 {
        return Ok(QualifiedRowSelection {
            choice: RowChoice::SharedDefault,
            initializer_needed,
        });
    }

    let mask = controls.len() - 1;
    let fingerprint = (supplied_hash >> 57) as u8;
    let mut position = (supplied_hash as usize) & mask;
    let mut step = 0usize;

    // The finite cycle cap is checked-entry policy, not a recovered native exit.
    for _ in 0..(controls.len() / 16) {
        let mut has_empty = false;
        // Native TZCNT visits matching lanes in ascending order. An empty
        // byte cannot stop this group before all key candidates are examined.
        for lane in 0..16usize {
            let index = position.wrapping_add(lane) & mask;
            let control = controls[index];
            if control == fingerprint && keys[index] == *query {
                return Ok(QualifiedRowSelection {
                    choice: RowChoice::Bucket(index),
                    initializer_needed,
                });
            }
            has_empty |= control == u8::MAX;
        }
        if has_empty {
            return Ok(QualifiedRowSelection {
                choice: RowChoice::SharedDefault,
                initializer_needed,
            });
        }
        step = step.wrapping_add(16);
        position = position.wrapping_add(step) & mask;
    }
    Err(SelectorInputError::NoNormalExit)
}
