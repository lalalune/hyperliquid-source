#![no_std]
#![forbid(unsafe_code)]
//! Value and one-slot store projection of node94 [0x5521d10, 0x5521d37).

/// The written GP values and the destination of the one eight-byte store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effects {
    pub rax: u64,
    pub rcx: u64,
    pub store_address: u64,
}

/// Compute the mask and replace a supplied image of the global qword.
///
/// Every `u64` input, entry-RCX value and bias bit pattern is admitted. `slot`
/// represents the writable eight bytes at linked VA 0x5788110 plus load bias;
/// its actual Rust address is unrelated. The returned address is a numeric
/// observation, never dereferenced. Original-memory correspondence requires a
/// valid writable slot, stable code and return control; see the packet proof.
/// RDI is unchanged. Original ABI, flags, faults and access traces are excluded.
pub fn apply(input: u64, entry_rcx: u64, load_bias: u64, slot: &mut [u8; 8]) -> Effects {
    let (mask, rcx) = if input == u64::MAX {
        (u64::MAX, entry_rcx)
    } else {
        ((1_u64 << (input & 63)) - 1, u64::from(input as u32))
    };
    slot.copy_from_slice(&mask.to_le_bytes());
    Effects {
        rax: mask,
        rcx,
        store_address: load_bias.wrapping_add(0x5788110),
    }
}
