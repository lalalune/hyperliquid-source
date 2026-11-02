#![no_std]
//! Ordered state projection of node94 [0x5632d90, 0x5632dbb).
//!
//! Both logical offsets name valid 32-byte regions in one mutable buffer.
//! This admits arbitrary byte-offset overlap, including identical regions.
//! Native address wrap, faults and concurrent mutation are outside the domain.

/// New safe-API bounds refusal, not an original target return or fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds;

fn region(offset: u64, length: usize) -> Result<usize, Bounds> {
    let offset = usize::try_from(offset).map_err(|_| Bounds)?;
    match offset.checked_add(32) {
        Some(end) if end <= length => Ok(offset),
        _ => Err(Bounds),
    }
}

/// Four ordered qword reads, byte swaps and writes, returning final raw RAX.
/// Each qword is read completely before its write; later reads observe earlier
/// writes. Bounds refusal happens before any write and preserves the buffer.
/// The result describes register bits, without assigning an original type.
pub fn copy_reverse(memory: &mut [u8], source: u64, destination: u64) -> Result<u64, Bounds> {
    let source = region(source, memory.len())?;
    let destination = region(destination, memory.len())?;
    let mut last = 0;
    for word in 0..4 {
        let start = source + 24 - word * 8;
        let block: [u8; 8] = memory[start..start + 8].try_into().unwrap();
        last = u64::from_le_bytes(block).swap_bytes();
        let output = destination + word * 8;
        memory[output..output + 8].copy_from_slice(&last.to_le_bytes());
    }
    Ok(last)
}
