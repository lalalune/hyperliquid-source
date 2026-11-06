#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use node115_varint_buffer_writer::{self as scalar, Error as ScalarError};

/// Logical wire order. Native source holds words before these twenty bytes;
/// no semantic address/hash name or native Rust layout is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub prefix: [u8; 20],
    pub words: [u64; 4],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeBoundary {
    Prefix,
    Field(usize),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBoundary {
    Prefix,
    Field { index: usize, stage: ScalarError },
}

/// Count the atomic twenty-byte prefix, then four ordered scalar encodings.
/// Errors expose pre-native-helper snapshots, not native recoverable errors.
pub fn count(record: &Record, counter: &mut u64) -> Result<(), SizeBoundary> {
    *counter = counter.checked_add(20).ok_or(SizeBoundary::Prefix)?;
    for (index, value) in record.words.iter().enumerate() {
        node115_varint_size_state::count_u64(*value, counter)
            .map_err(|_| SizeBoundary::Field(index))?;
    }
    Ok(())
}

/// Reserve the full fixed prefix before writing any byte, then serialize the
/// four ordered fields. Existing bytes and partial scalar markers survive a
/// later allocation refusal. Actual alloc::Vec supplies allocation and storage.
pub fn write(record: &Record, vector: &mut Vec<u8>) -> Result<(), WriteBoundary> {
    if vector.capacity() - vector.len() < 20 {
        vector.try_reserve(20).map_err(|_| WriteBoundary::Prefix)?;
    }
    vector.extend_from_slice(&record.prefix);
    for (index, value) in record.words.iter().enumerate() {
        scalar::write_u64(vector, *value).map_err(|stage| WriteBoundary::Field { index, stage })?;
    }
    Ok(())
}
