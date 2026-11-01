#![no_std]
#![forbid(unsafe_code)]

//! Safe memory projection of node #94's complete 0x55716a0..0x557170a leaf.
//! This is independently authored Rust, not the captured calling convention.

/// Where the single payload byte is read after the header has been stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Payload {
    /// A byte from storage disjoint from `output`, stable through this call.
    External(u8),
    /// An offset into `output`; this can observe a just-written header byte.
    Output(usize),
}

/// New safe-API refusals; these are not recovered returns of the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    OutputTooShort,
    PayloadOutsideOutput,
}

/// Write the leaf's prefix and one byte, returning its raw 2/3/4 byte count.
///
/// All `u64` lengths are admitted. The full-width unsigned length selects the
/// path; arithmetic for the header uses its low 32 bits. Both memory premises
/// are checked before mutation (output capacity first). Refusal leaves every
/// byte unchanged. Success leaves every byte after the returned count intact.
///
/// `Payload::Output` models overlap with any byte in this slice, including its
/// unwritten suffix. `External` assumes disjoint, stable storage. Volatile or
/// concurrently modified memory, invalid pointers, ABI effects, and the meaning
/// of the numeric header tags are outside this value/memory projection.
pub fn encode(output: &mut [u8], length: u64, payload: Payload) -> Result<u32, Refusal> {
    let (header, header_width, total) = if length <= 31 {
        ((length as u32).wrapping_mul(8).wrapping_add(1), 1, 2)
    } else if length <= 4095 {
        ((length as u32).wrapping_mul(16).wrapping_add(5), 2, 3)
    } else {
        ((length as u32).wrapping_mul(16).wrapping_add(13), 4, 4)
    };
    if output.len() < total {
        return Err(Refusal::OutputTooShort);
    }
    if let Payload::Output(index) = payload {
        if index >= output.len() {
            return Err(Refusal::PayloadOutsideOutput);
        }
    }
    output[..header_width].copy_from_slice(&header.to_le_bytes()[..header_width]);
    let byte = match payload {
        Payload::External(byte) => byte,
        Payload::Output(index) => output[index],
    };
    output[total - 1] = byte;
    Ok(total as u32)
}
