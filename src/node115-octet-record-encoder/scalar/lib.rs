#![no_std]
//! Logical u64 byte-vector writer from node115 0x5822910..0x5822b90.
//! Real alloc::Vec is used. Errors expose native allocation-failure boundaries,
//! not an assertion that the native panic/abort path returns a Result.
extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    PrefixGrowth,
    PayloadGrowth,
}

fn reserve(vector: &mut Vec<u8>, additional: usize, stage: Error) -> Result<(), Error> {
    if vector.capacity() - vector.len() < additional {
        vector.try_reserve(additional).map_err(|_| stage)?;
    }
    Ok(())
}

/// Append one minimally encoded u64, preserving any committed prefix marker on
/// a later payload-growth refusal. Caller bytes already in the vector survive.
/// This is the complete 1/3/5/9-byte value family, not the separate size counter.
/// Actual byte-vector allocation uses the standard Rust allocator. Pointer,
/// capacity-object ABI, allocator identity and native panic payloads are open.
pub fn write_u64(vector: &mut Vec<u8>, value: u64) -> Result<(), Error> {
    if value < 251 {
        reserve(vector, 1, Error::PrefixGrowth)?;
        vector.push(value as u8);
        return Ok(());
    }
    let (marker, width) = if value < 65_536 {
        (251, 2)
    } else if value < (1_u64 << 32) {
        (252, 4)
    } else {
        (253, 8)
    };
    reserve(vector, 1, Error::PrefixGrowth)?;
    vector.push(marker);
    reserve(vector, width, Error::PayloadGrowth)?;
    vector.extend_from_slice(&value.to_le_bytes()[..width]);
    Ok(())
}
