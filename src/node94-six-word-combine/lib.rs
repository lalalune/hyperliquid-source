#![no_std]
#![forbid(unsafe_code)]
//! Ordered byte-image projection of node94 [0x565f000, 0x565f20c).
//!
//! The source is two adjacent six-word values. The first product is stored
//! before the second input is loaded, so every partial/exact overlap matters.
//! This API preserves the measured arithmetic even for negative-times-zero
//! and signed 448-bit wrap. It does not assign a number-system purpose.

/// New API refusal: a required source/destination span is absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingSpan;

/// Final value registers; pointer registers and flags are not an ABI promise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outcome {
    /// R8 through R13, also stored as six little-endian destination words.
    pub words: [u64; 6],
    pub rax: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub r14: u64,
    pub r15: u64,
}

fn load(image: &[u8], at: usize) -> [u64; 6] {
    core::array::from_fn(|i| {
        let begin = at + i * 8;
        let mut word = [0; 8];
        word.copy_from_slice(&image[begin..begin + 8]);
        u64::from_le_bytes(word)
    })
}

fn store(image: &mut [u8], at: usize, words: &[u64; 6]) {
    for (i, word) in words.iter().enumerate() {
        let begin = at + i * 8;
        image[begin..begin + 8].copy_from_slice(&word.to_le_bytes());
    }
}

fn negate(words: &mut [u64; 6]) {
    let mut carry = 1_u128;
    for word in words {
        let sum = u128::from(!*word) + carry;
        *word = sum as u64;
        carry = sum >> 64;
    }
}

fn product(mut words: [u64; 6], coefficient: i64) -> ([u64; 7], u128) {
    let negative = coefficient < 0;
    let magnitude = coefficient.unsigned_abs();
    if negative {
        negate(&mut words);
    }
    let last_multiply = u128::from(words[5]) * u128::from(magnitude);
    let mut result = [0; 7];
    let mut carry = 0_u128;
    for i in 0..6 {
        let sum = u128::from(words[i]) * u128::from(magnitude) + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }
    result[6] = carry as u64;
    if negative {
        // The discarded carry of six-word negation is deliberately not restored.
        result[6] = result[6].wrapping_sub(magnitude);
    }
    (result, last_multiply)
}

/// Apply the complete helper's ordered memory/value projection.
///
/// `source..source+96` and `destination..destination+48` must exist in `image`.
/// All bytewise overlaps and both full-width signed coefficients are admitted.
/// A missing span refuses before mutation; this is not an original fault model.
/// Correspondence requires ordinary stable mapped memory and nonwrapping target
/// addresses, excluding aliases with code/control/stack storage and concurrent
/// mutation. Pointer ABI, flags, timing and caller algorithm are outside scope.
pub fn combine(
    image: &mut [u8],
    source: usize,
    destination: usize,
    first_coefficient: i64,
    second_coefficient: i64,
) -> Result<Outcome, MissingSpan> {
    if source.checked_add(96).is_none_or(|end| end > image.len())
        || destination
            .checked_add(48)
            .is_none_or(|end| end > image.len())
    {
        return Err(MissingSpan);
    }

    let (first, _) = product(load(image, source), first_coefficient);
    let first_low: [u64; 6] = core::array::from_fn(|i| first[i]);
    store(image, destination, &first_low);
    let (second, last_multiply) = product(load(image, source + 48), second_coefficient);

    let mut sum = [0_u64; 7];
    let mut carry = 0_u128;
    for i in 0..7 {
        let wide = u128::from(first[i]) + u128::from(second[i]) + carry;
        sum[i] = wide as u64;
        carry = wide >> 64;
    }
    let negative = sum[6] >> 63 != 0;
    let mut words = core::array::from_fn(|i| (sum[i] >> 30) | (sum[i + 1] << 34));
    if negative {
        negate(&mut words);
    }
    store(image, destination, &words);
    Ok(Outcome {
        words,
        rax: last_multiply as u64,
        rdx: (last_multiply >> 64) as u64,
        rbx: u64::from(negative),
        r14: if negative { u64::MAX } else { 0 },
        r15: second[6],
    })
}
