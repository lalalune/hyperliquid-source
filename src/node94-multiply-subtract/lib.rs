//! Safe value projection of node94 ELF VAs 0x565ee40 and 0x565eea0.
//!
//! Words are ordered least significant first. Inputs represent stable entry
//! snapshots; returned words model destination stores and `return_value`
//! models RAX. This API does not expose the native pointer ABI or shared-memory
//! effects when source and destination alias. See the evidence packet.
#![no_std]
#![forbid(unsafe_code)]

pub struct WideOutput {
    pub words: [u64; 3],
    pub return_value: u64,
}

pub struct NarrowOutput {
    pub words: [u64; 2],
    pub return_value: u64,
}

/// Subtract a full 192-bit product, add the 128-bit operand back on borrow,
/// and replace the top word with the scalar minus that borrow.
///
/// The top subtraction result and carry out of the low-128 add-back are
/// discarded. The adjusted scalar is both the stored top word and RAX.
pub fn subtract_wide(out: [u64; 3], input: [u64; 2], scalar: u64) -> WideOutput {
    let first = u128::from(input[0]) * u128::from(scalar);
    let second = u128::from(input[1]) * u128::from(scalar);
    let middle = (first >> 64) + u128::from(second as u64);
    let product_top = (second >> 64) as u64 + (middle >> 64) as u64;
    let product_low = u128::from(first as u64) | (middle << 64);
    let original_low = u128::from(out[0]) | (u128::from(out[1]) << 64);
    let borrow = (out[2], original_low) < (product_top, product_low);
    let difference = original_low.wrapping_sub(product_low);
    let operand = u128::from(input[0]) | (u128::from(input[1]) << 64);
    let corrected = if borrow {
        difference.wrapping_add(operand)
    } else {
        difference
    };
    let adjusted = scalar.wrapping_sub(u64::from(borrow));
    WideOutput {
        words: [corrected as u64, (corrected >> 64) as u64, adjusted],
        return_value: adjusted,
    }
}

/// Subtract the low 64 bits of the scalar product, then store/return scalar.
/// The native body does not read an entry second destination word.
pub fn subtract_narrow(out0: u64, input0: u64, scalar: u64) -> NarrowOutput {
    let low = out0.wrapping_sub(input0.wrapping_mul(scalar));
    NarrowOutput {
        words: [low, scalar],
        return_value: scalar,
    }
}
