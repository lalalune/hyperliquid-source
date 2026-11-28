//! Node #115 `l1/src/abci/abci_hash.rs` state-root reduction tree MessagePack preimage
//! encoder and root-selector cell integration.
//!
//! Binary anchors:
//! - `RE-009-node115-abci-crate-map`: `0x2bb37c0`, `0x548d8c0`, `0x548dad0` (`abci_hash.rs:28:37`)
//! - `RE-017-abci-root-tree-115`: 59-slot root capture, MessagePack array/u64/0xd9-hex encoding
//! - `RE-009-node115-root-digest-selector` / `RE-009-node115-root-digest-cell-writer`

pub use node115_abci_blake3::{
    Blake3Hasher, IV as BLAKE3_IV, blake3_hash, compute_leaf_root, compute_preimage_root,
};
pub use node115_abci_checkpoint_replay_fixture::{
    RootSelectorCell, SelectorTrace, select_root_impl,
};

/// Top-level capture slot count observed in node #115 (`RE-017-abci-root-tree-115`).
pub const ROOT_CAPTURE_SLOT_COUNT: usize = 59;

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReductionNode {
    /// Leaf 32-byte digest serialized as `d9 42 "0x" <64 lowercase hex>`.
    Leaf([u8; 32]),
    /// Nested indexed child vector.
    Nested(Vec<ReductionRow>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReductionRow {
    pub index: u64,
    pub value: ReductionNode,
}

/// Outcomes supplied at the top-level #115 capture boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureSlot {
    /// No child was produced for the initialized slot.
    Empty,
    /// The child reduced to the selected omit status.
    Omitted,
    Value(ReductionNode),
}

/// Collect the surviving rows without renumbering intervening empty slots.
pub fn reduce_top_level_capture(
    slots: [CaptureSlot; ROOT_CAPTURE_SLOT_COUNT],
) -> Vec<ReductionRow> {
    slots
        .into_iter()
        .enumerate()
        .filter_map(|(index, slot)| match slot {
            CaptureSlot::Value(value) => Some(ReductionRow {
                index: index as u64,
                value,
            }),
            CaptureSlot::Empty | CaptureSlot::Omitted => None,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    ArrayLengthExceedsU32(usize),
}

fn push_array_header(out: &mut Vec<u8>, len: usize) -> Result<(), EncodeError> {
    if len <= 15 {
        out.push(0x90 | (len as u8));
    } else if len <= 0xffff {
        out.push(0xdc);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if let Ok(len32) = u32::try_from(len) {
        out.push(0xdd);
        out.extend_from_slice(&len32.to_be_bytes());
    } else {
        return Err(EncodeError::ArrayLengthExceedsU32(len));
    }
    Ok(())
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    if value <= 0x7f {
        out.push(value as u8);
    } else if value <= 0xff {
        out.push(0xcc);
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xcd);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xffff_ffff {
        out.push(0xce);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn push_leaf_hex(out: &mut Vec<u8>, digest: &[u8; 32]) {
    // MessagePack str8 (0xd9), length 66 (0x42): "0x" + 64 lowercase hex chars.
    out.push(0xd9);
    out.push(0x42);
    out.extend_from_slice(b"0x");
    for &b in digest {
        out.push(HEX_LOWER[(b >> 4) as usize]);
        out.push(HEX_LOWER[(b & 0x0f) as usize]);
    }
}

/// Encode a state-root reduction tree into the exact MessagePack byte preimage
/// documented in `RE-017-abci-root-tree-115`.
pub fn encode_reduction_tree(rows: &[ReductionRow]) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_rows_into(&mut out, rows)?;
    Ok(out)
}

/// Compute the exact 32-byte node #115 BLAKE3 state root over a reduction tree
/// (`0x548dad0 -> slot 0x64e7820 -> 0x41c5140 -> 0x160b3a0 / 0x160bcd0`).
pub fn compute_reduction_tree_root(rows: &[ReductionRow]) -> Result<[u8; 32], EncodeError> {
    let preimage = encode_reduction_tree(rows)?;
    Ok(compute_preimage_root(&preimage))
}

fn encode_rows_into(out: &mut Vec<u8>, rows: &[ReductionRow]) -> Result<(), EncodeError> {
    push_array_header(out, rows.len())?;
    for row in rows {
        out.push(0x92); // 2-element array: [index, value]
        push_u64(out, row.index);
        match &row.value {
            ReductionNode::Leaf(digest) => push_leaf_hex(out, digest),
            ReductionNode::Nested(children) => encode_rows_into(out, children)?,
        }
    }
    Ok(())
}
