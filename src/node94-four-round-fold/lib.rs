//! Numeric projection of node #94 [0x565d8a0, 0x565da24).
//!
//! Inputs are four little-endian qwords from entry RSI, four from entry RBX,
//! and entry RCX. All numeric inputs are admitted. Original memory must permit
//! all reads with stable values; this API supplies their snapshots. It makes
//! no inverse, primality, modulus, or caller-domain assumption. It reproduces
//! the nine written general-purpose registers, not the custom machine ABI.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Four rounds with the observed low-word fold and discarded fold carry.
///
/// The function does not write memory. See the evidence proof for the exact
/// register correspondence, stable-read premise, and full-domain bounds.
pub fn fold(mut input: [u64; 4], operand: [u64; 4], coefficient: u64) -> Registers {
    let mut multipliers = [0_u64; 4];
    for round in 0..4 {
        let q = input[0].wrapping_mul(coefficient);
        multipliers[round] = q;
        let low = u128::from(q) * u128::from(operand[0]) + u128::from(input[0]);
        let mut carry = (low as u64).wrapping_add((low >> 64) as u64);
        let mut next = [0_u64; 4];
        for lane in 1..4 {
            let sum = u128::from(q) * u128::from(operand[lane])
                + u128::from(input[lane])
                + u128::from(carry);
            next[lane - 1] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        next[3] = carry;
        input = next;
    }
    Registers {
        rax: input[0],
        rdx: input[3],
        r9: input[3],
        r10: multipliers[1],
        r11: multipliers[2],
        r12: multipliers[3],
        r13: input[0],
        r14: input[1],
        r15: input[2],
    }
}
