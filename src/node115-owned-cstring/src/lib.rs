#![no_std]
//! Whole selected byte-slice converter; not arbitrary native finalizer states.
extern crate alloc;
use alloc::vec::Vec;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Allocation,
    InteriorNul { position: usize, bytes: Vec<u8> },
}
/// Allocate/copy first, reject the first NUL with the unmodified owned copy,
/// otherwise append one terminator in the reserved byte. Failure to allocate
/// is a safe observable boundary, not a promise the native OOM path returns.
pub fn convert(input: &[u8]) -> Result<Vec<u8>, Error> {
    let capacity = input
        .len()
        .checked_add(1)
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(Error::Allocation)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Allocation)?;
    bytes.extend_from_slice(input);
    if let Some(position) = input.iter().position(|b| *b == 0) {
        return Err(Error::InteriorNul { position, bytes });
    }
    bytes.push(0);
    Ok(bytes)
}
