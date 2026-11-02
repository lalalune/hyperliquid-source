#![no_std]
#![forbid(unsafe_code)]
//! Value/image projection of node94 [0x565e960,0x565ea92).
//! The fifth input words have a bit-mask role, not unrestricted multiplication.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rbp: u64,
    pub r8: u64,
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
    pub words: [u64; 5],
    pub registers: Registers,
}

struct Product {
    words: [u64; 5],
    magnitude: u64,
    last_multiply: u128,
}

fn product(mut words: [u64; 5], coefficient: u64) -> Product {
    let negative = coefficient >> 63 != 0;
    let magnitude = if negative {
        coefficient.wrapping_neg()
    } else {
        coefficient
    };
    if negative {
        let mut carry = true;
        for word in &mut words {
            let (value, next) = (!*word).overflowing_add(u64::from(carry));
            *word = value;
            carry = next;
        }
    }
    let mut result = [0_u64; 5];
    let mut carry = 0_u64;
    for i in 0..4 {
        let wide = u128::from(words[i]) * u128::from(magnitude) + u128::from(carry);
        result[i] = wide as u64;
        carry = (wide >> 64) as u64;
    }
    result[4] = carry.wrapping_sub(words[4] & magnitude);
    Product {
        words: result,
        magnitude,
        last_multiply: u128::from(words[3]) * u128::from(magnitude),
    }
}

/// All input words and coefficient bits are admitted. Coefficients use signed
/// i64 interpretation, including MIN; the fifth-word mask is retained exactly.
/// This reports values, not an original Rust signature or native ABI.
pub fn combine(a: [u64; 5], b: [u64; 5], coefficient_a: u64, coefficient_b: u64) -> Observation {
    let first = product(a, coefficient_a);
    let second = product(b, coefficient_b);
    let mut words = [0_u64; 5];
    let mut carry = 0_u64;
    for (i, word) in words.iter_mut().enumerate() {
        let wide = u128::from(first.words[i]) + u128::from(second.words[i]) + u128::from(carry);
        *word = wide as u64;
        carry = (wide >> 64) as u64;
    }
    Observation {
        words,
        registers: Registers {
            rax: second.last_multiply as u64,
            rdx: (second.last_multiply >> 64) as u64,
            rbx: second.magnitude,
            rcx: second.words[4],
            rbp: words[4],
            r8: words[0],
            r9: words[1],
            r10: words[2],
            r11: words[3],
            r12: second.words[0],
            r13: second.words[1],
            r14: second.words[2],
            r15: second.words[3],
        },
    }
}

/// Project a normally returning call in one nonwrapping ordinary byte image.
/// Input is two consecutive five-word arrays; output is five words. All data
/// aliases, including unaligned partial overlaps, use the entry input snapshot.
/// `None` is a new finite-image refusal, leaves memory unchanged and models no
/// target fault. Numeric offsets are never converted to native addresses.
pub fn apply_image(
    image: &mut [u8],
    source: u64,
    destination: u64,
    coefficient_a: u64,
    coefficient_b: u64,
) -> Option<Registers> {
    let source = usize::try_from(source).ok()?;
    let destination = usize::try_from(destination).ok()?;
    let source_end = source.checked_add(80)?;
    let destination_end = destination.checked_add(40)?;
    if source_end > image.len() || destination_end > image.len() {
        return None;
    }
    let mut input = [0_u64; 10];
    for (i, word) in input.iter_mut().enumerate() {
        let begin = source + i * 8;
        *word = u64::from_le_bytes(image[begin..begin + 8].try_into().ok()?);
    }
    let result = combine(
        input[..5].try_into().ok()?,
        input[5..].try_into().ok()?,
        coefficient_a,
        coefficient_b,
    );
    for (i, word) in result.words.iter().enumerate() {
        let begin = destination + i * 8;
        image[begin..begin + 8].copy_from_slice(&word.to_le_bytes());
    }
    Some(result.registers)
}
