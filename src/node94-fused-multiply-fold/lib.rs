#![no_std]
#![forbid(unsafe_code)]
//! Raw prepared-register/value projection of node94 [0x565d440,0x565d752).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prepared {
    pub rax: u64,
    pub r9: u64,
    pub r10: u64,
    pub r14: u64,
    pub r12: u64,
    pub rbp: u64,
    pub r15: u64,
    pub r8: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub words: [u64; 4],
    pub registers: Registers,
}

fn add_product(state: &mut [u64; 6], a: [u64; 4], digit: u64) {
    let mut carry = 0_u64;
    for i in 0..4 {
        let wide =
            u128::from(a[i]) * u128::from(digit) + u128::from(state[i + 1]) + u128::from(carry);
        state[i + 1] = wide as u64;
        carry = (wide >> 64) as u64;
    }
    state[5] = state[5].wrapping_add(carry);
}

fn fold(state: &mut [u64; 6], modulus: [u64; 4], factor: u64) -> (u64, u64, u64) {
    let quotient = state[0].wrapping_mul(factor);
    let product = u128::from(state[0]) + u128::from(quotient) * u128::from(modulus[0]);
    let residue = (product as u64).wrapping_add((product >> 64) as u64);
    state.copy_within(1..6, 0);
    state[5] = 0;
    let mut carry = residue;
    for i in 0..3 {
        let wide = u128::from(quotient) * u128::from(modulus[i + 1])
            + u128::from(state[i])
            + u128::from(carry);
        state[i] = wide as u64;
        carry = (wide >> 64) as u64;
    }
    let product_carry = carry;
    for word in &mut state[3..] {
        let (value, overflow) = word.overflowing_add(carry);
        *word = value;
        carry = u64::from(overflow);
    }
    (quotient, residue, product_carry)
}

/// All prepared registers, input words and factor bits are independent.
/// `output_address` is the supplied value of original [entry RSP+8], never a
/// dereferenced pointer. No inverse, reduction or caller-consistency condition
/// is imposed. See PROOF.md for the stable-memory and control-data premises.
pub fn evaluate(
    prepared: Prepared,
    a: [u64; 4],
    later_b: [u64; 3],
    modulus: [u64; 4],
    output_address: u64,
) -> Observation {
    let mut state = [0_u64; 6];
    state[0] = prepared.r9;
    let first = u128::from(prepared.rax) * u128::from(prepared.r14) + u128::from(prepared.r10);
    state[1] = first as u64;
    let second = u128::from(prepared.r15) * u128::from(prepared.r12) + (first >> 64);
    state[2] = second as u64;
    let third = u128::from(prepared.r15) * u128::from(prepared.rbp) + (second >> 64);
    state[3] = third as u64;
    state[4] = (third >> 64) as u64;
    let mut last_interleaved_residue = 0;
    for digit in later_b {
        add_product(&mut state, a, digit);
        let (_, residue, _) = fold(&mut state, modulus, prepared.r8);
        last_interleaved_residue = residue;
    }
    let (quotient, _, product_carry) = fold(&mut state, modulus, prepared.r8);
    let saved = [state[0], state[1], state[2], state[3]];
    let mut difference = [0_u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (partial, first_borrow) = state[i].overflowing_sub(modulus[i]);
        let (value, second_borrow) = partial.overflowing_sub(u64::from(borrow));
        difference[i] = value;
        borrow = first_borrow || second_borrow;
    }
    let (top_difference, final_borrow) = state[4].overflowing_sub(u64::from(borrow));
    let words = if final_borrow { saved } else { difference };
    Observation {
        words,
        registers: Registers {
            rax: saved[0],
            rdx: product_carry,
            rbx: saved[1],
            rbp: saved[3],
            rdi: last_interleaved_residue,
            rsi: output_address,
            r9: words[3],
            r10: top_difference,
            r11: quotient,
            r12: saved[2],
            r13: words[0],
            r14: words[1],
            r15: words[2],
        },
    }
}

fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<core::ops::Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}

fn read_words<const N: usize>(raw: &[u8]) -> Option<[u64; N]> {
    let mut words = [0; N];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u64::from_le_bytes(raw.get(i * 8..i * 8 + 8)?.try_into().ok()?);
    }
    Some(words)
}

/// Stable finite byte-image adapter. The output address is supplied separately
/// from the original stack slot; original stack/control storage is disjoint
/// from this image. All data aliases within the image are allowed. None is a
/// new refusal, never a target fault, and preserves the image without writes.
pub fn apply_image(
    image: &mut [u8],
    base: u64,
    a_address: u64,
    b_address: u64,
    modulus_address: u64,
    output_address: u64,
    prepared: Prepared,
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1_u128 << 64) {
        return None;
    }
    let output = span(image, base, output_address, 32)?;
    let a = read_words::<4>(&image[span(image, base, a_address, 32)?])?;
    let later_b = read_words::<3>(&image[span(image, base, b_address.wrapping_add(8), 24)?])?;
    let modulus = read_words::<4>(&image[span(image, base, modulus_address, 32)?])?;
    let result = evaluate(prepared, a, later_b, modulus, output_address);
    for (word, bytes) in result.words.iter().zip(image[output].chunks_exact_mut(8)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    Some(result.registers)
}
