//! Node #115 `db/src/block_reader.rs` offline SSTable block-handle slicing and
//! indexed artifact variant recognition.
//!
//! Binary anchors (`RE-009-node115-db-crate-map`, `RE-009-node115-abci-apply-block-guards-and-history-prune`):
//! - `0x2a191e0..0x2a195a7` (`block_reader.rs:27:70`, `BlockReader::block` at `0x43f132`)
//! - `0x2b2be60..0x2b2c4f1` (`block_reader.rs:29:26`)
//! - `0x2a0acc0..0x2a0b327` (`block_reader.rs:45:114`, `BlockReader::range_query_inclusive` at `0x449de1`)

use std::collections::BTreeMap;

pub use node115_indexed_artifact_variant::IndexedArtifactVariant;

use node115_block_handle_codec::{BlockHandle, DecodeStatus, InputSlice, decode_into};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReadError {
    BadHandle(DecodeStatus),
    OutOfBounds {
        offset: u64,
        size: u64,
        backing_len: usize,
    },
}

/// Offline slice-backed reader using the exact node #115 `BlockHandle` wire codec.
#[derive(Clone, Copy, Debug)]
pub struct OfflineBlockReader<'a> {
    backing: &'a [u8],
}

impl<'a> OfflineBlockReader<'a> {
    pub const fn new(backing: &'a [u8]) -> Self {
        Self { backing }
    }

    pub const fn len(&self) -> usize {
        self.backing.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.backing.is_empty()
    }

    /// Decode a `BlockHandle` from `handle_bytes` and return the referenced slice
    /// from `backing` along with the remaining unread handle cursor bytes.
    pub fn read_encoded_handle<'h>(
        &self,
        handle_bytes: &'h [u8],
    ) -> Result<(BlockHandle, &'a [u8], &'h [u8]), BlockReadError> {
        let mut handle = BlockHandle::default();
        let mut input = InputSlice::new(handle_bytes);
        let status = decode_into(&mut handle, &mut input);
        if !status.is_ok() {
            return Err(BlockReadError::BadHandle(status));
        }
        let slice = self.read_handle(handle)?;
        Ok((handle, slice, input.remaining()))
    }

    pub fn read_handle(&self, handle: BlockHandle) -> Result<&'a [u8], BlockReadError> {
        let start = usize::try_from(handle.offset).map_err(|_| BlockReadError::OutOfBounds {
            offset: handle.offset,
            size: handle.size,
            backing_len: self.backing.len(),
        })?;
        let size = usize::try_from(handle.size).map_err(|_| BlockReadError::OutOfBounds {
            offset: handle.offset,
            size: handle.size,
            backing_len: self.backing.len(),
        })?;
        let end = start.checked_add(size).ok_or(BlockReadError::OutOfBounds {
            offset: handle.offset,
            size: handle.size,
            backing_len: self.backing.len(),
        })?;
        self.backing
            .get(start..end)
            .ok_or(BlockReadError::OutOfBounds {
                offset: handle.offset,
                size: handle.size,
                backing_len: self.backing.len(),
            })
    }
}

/// Offline height-indexed block store modeling `BlockReader::block` (`0x2a191e0`)
/// and `BlockReader::range_query_inclusive` (`0x2a0acc0`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexedBlockReader {
    blocks: BTreeMap<u64, Vec<u8>>,
}

impl IndexedBlockReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_block(&mut self, height: u64, payload: Vec<u8>) {
        self.blocks.insert(height, payload);
    }

    /// Point lookup matching `BlockReader::block` (`0x2a191e0`).
    pub fn block(&self, height: u64) -> Option<&[u8]> {
        self.blocks.get(&height).map(Vec::as_slice)
    }

    /// Inclusive height-range query matching `BlockReader::range_query_inclusive` (`0x2a0acc0`).
    pub fn range_query_inclusive(&self, start: u64, end: u64) -> Vec<(u64, &[u8])> {
        if start > end {
            return Vec::new();
        }
        self.blocks
            .range(start..=end)
            .map(|(&h, v)| (h, v.as_slice()))
            .collect()
    }
}
