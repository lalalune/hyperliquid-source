//! Conditional byte projection of the node #94 QC row's prior successful reads.
//!
//! This models only the three copy ranges in the straight-line native corridor
//! `0x4c7e546..0x4c7e5f7`. The caller supplies already successful raw20 and
//! two opaque 32-byte group output snapshots. In the native row reader those
//! results occupy a reused stack slot, and the first group is staged before
//! the second call. It does not parse those groups or decide
//! whether the native decoder can reach this corridor from a wire message.
//! The success tag at `+0x00` and recovery byte at `+0x60` are written
//! outside this corridor and are deliberately not changed here.

/// Physical result extent: an eight-byte result tag plus one 0x60-byte row.
pub const QC_ROW_RESULT_BYTES: usize = 0x68;

/// Copy the previously decoded row fields into their observed result offsets.
///
/// The native corridor also leaves `+0x1c..+0x20` and `+0x61..+0x68`
/// untouched. This safe projection preserves those bytes in `output`.
/// It expresses final bytes, not native store order, aliasing or output ABI.
pub fn copy_prior_success_fields(
    output: &mut [u8; QC_ROW_RESULT_BYTES],
    raw20: &[u8; 20],
    first_group: &[u8; 32],
    second_group: &[u8; 32],
) {
    output[0x08..0x1c].copy_from_slice(raw20);
    output[0x20..0x40].copy_from_slice(first_group);
    output[0x40..0x60].copy_from_slice(second_group);
}
