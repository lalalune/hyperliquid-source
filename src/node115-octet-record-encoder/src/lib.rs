#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use node115_varint_buffer_writer::{self as scalar, Error as ScalarError};

/// Logical wire values, not the native pointer-containing source layout.
/// The trailing byte is raw; no boolean interpretation is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub words: [u64; 8],
    pub trailer: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeBoundary {
    Field(usize),
    Trailer,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBoundary {
    Field { index: usize, stage: ScalarError },
    Trailer,
}

/// Preserve the exact partial count on the pre-native-overflow-helper boundary.
/// This is not an assertion that the captured failure path returns an error.
pub fn count(record: &Record, counter: &mut u64) -> Result<(), SizeBoundary> {
    for (index, value) in record.words.iter().enumerate() {
        node115_varint_size_state::count_u64(*value, counter)
            .map_err(|_| SizeBoundary::Field(index))?;
    }
    *counter = counter.checked_add(1).ok_or(SizeBoundary::Trailer)?;
    Ok(())
}

/// Write all eight ordered words then one unnormalized byte to a real vector.
/// Prior fields and a current scalar's marker remain on a later growth refusal.
/// Safe boundary enums do not reproduce original fatal/panic/Result ABI.
pub fn write(record: &Record, vector: &mut Vec<u8>) -> Result<(), WriteBoundary> {
    for (index, value) in record.words.iter().enumerate() {
        scalar::write_u64(vector, *value).map_err(|stage| WriteBoundary::Field { index, stage })?;
    }
    if vector.len() == vector.capacity() {
        vector.try_reserve(1).map_err(|_| WriteBoundary::Trailer)?;
    }
    vector.push(record.trailer);
    Ok(())
}
