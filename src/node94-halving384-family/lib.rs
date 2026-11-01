//! Complete node94 384-bit parity-add/halve core and single/repeated wrappers.
//! Numeric snapshots and a safe image API; see the evidence packet for ABI limits.
#![no_std]
#![forbid(unsafe_code)]

pub type Words = [u64; 6];
const ZERO: Words = [0; 6];
const ONE: Words = [1, 0, 0, 0, 0, 0];
const LOW: u64 = (1 << 63) - 1;

/// Core's six result registers R8..R13 and six other written GP registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Core {
    pub words: Words,
    pub rax: u64,
    pub rsi: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub r14: u64,
    pub r15: u64,
}

fn sum(a: Words, b: Words) -> (Words, u64) {
    let mut out = ZERO;
    let mut carry = 0u128;
    for i in 0..6 {
        let total = a[i] as u128 + b[i] as u128 + carry;
        out[i] = total as u64;
        carry = total >> 64;
    }
    (out, carry as u64)
}

fn difference(a: Words, b: Words) -> (Words, bool) {
    let mut out = ZERO;
    let mut borrow = false;
    for i in 0..6 {
        let (v, first) = a[i].overflowing_sub(b[i]);
        let (v, second) = v.overflowing_sub(borrow as u64);
        out[i] = v;
        borrow = first || second;
    }
    (out, borrow)
}

fn half(words: Words, high: u64) -> Words {
    let mut result = ZERO;
    for i in 0..5 {
        result[i] = (words[i] >> 1) | (words[i + 1] << 63);
    }
    result[5] = (words[5] >> 1) | (high << 63);
    result
}

fn next(input: Words, correction: Words) -> Words {
    let selected = if input[0] & 1 == 1 { correction } else { ZERO };
    let (total, high) = sum(input, selected);
    half(total, high)
}

/// Full [0x5656b20,0x5656bb9) value relation for arbitrary 384-bit operands.
pub fn step(input: Words, correction: Words) -> Core {
    let words = next(input, correction);
    Core {
        words,
        rax: words[2] & LOW,
        rsi: words[5] & LOW,
        rbx: words[3] & LOW,
        rbp: words[4] & LOW,
        r14: words[0] & LOW,
        r15: words[1] & LOW,
    }
}

// Both operands are below the positive odd divisor; their sum is below 2D.
fn reduced_sum(a: Words, b: Words, divisor: Words) -> Words {
    let (total, high) = sum(a, b);
    let (reduced, borrow) = difference(total, divisor);
    if high != 0 || !borrow { reduced } else { total }
}

// Horner evaluation over all 384 multiplier bits, from most to least significant.
fn product_mod(a: Words, b: Words, divisor: Words) -> Words {
    let mut result = ZERO;
    for bit in (0..384).rev() {
        result = reduced_sum(result, result, divisor);
        if (b[bit / 64] >> (bit % 64)) & 1 != 0 {
            result = reduced_sum(result, a, divisor);
        }
    }
    result
}

fn repeated_value(mut value: Words, correction: Words, raw_count: u64) -> Words {
    let low_count = raw_count as u32;
    let passes = if low_count == 0 {
        1u64 << 32
    } else {
        low_count as u64
    };
    let initial = passes.min(384);
    for _ in 0..initial {
        value = next(value, correction);
    }
    let mut remaining = passes - initial;
    if remaining == 0 || value == ZERO {
        return value;
    }
    // The first 384 steps put every positive value in 1..=D, including unreduced inputs.
    let divisor = if correction[0] & 1 == 0 {
        difference(correction, ONE).0
    } else {
        correction
    };
    if value == divisor {
        return value;
    }
    let mut power = sum(half(divisor, 0), ONE).0;
    while remaining != 0 {
        if remaining & 1 != 0 {
            value = product_mod(value, power, divisor);
        }
        remaining >>= 1;
        if remaining != 0 {
            power = product_mod(power, power, divisor);
        }
    }
    if value == ZERO { divisor } else { value }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wrapper {
    Single,
    Repeated { raw_count: u64 },
}

/// Complete selected wrapper observations; restored saved-register values are excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rcx: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
}

fn offset(image: &[u8], base: u64, address: u64) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    if start.checked_add(48)? > image.len() {
        return None;
    }
    Some(start)
}
fn load(image: &[u8], start: usize) -> Words {
    let mut words = ZERO;
    for i in 0..6 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&image[start + 8 * i..start + 8 * i + 8]);
        words[i] = u64::from_le_bytes(bytes);
    }
    words
}

/// Single [0x5656bc0,0x5656c2a) or repeated [0x5656aa0,0x5656b0b) wrapper.
/// Both 48-byte operands are read before any destination write, even for zero or
/// even input. All data aliases are admitted; stable ordinary memory and original
/// control-stack disjointness are required for native correspondence. `None` is
/// this safe API's unchanged-image range refusal, not an original target result.
pub fn apply(
    image: &mut [u8],
    base: u64,
    destination: u64,
    input: u64,
    correction: u64,
    wrapper: Wrapper,
) -> Option<Registers> {
    if base as u128 + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let dest = offset(image, base, destination)?;
    let source = offset(image, base, input)?;
    let adjustment = offset(image, base, correction)?;
    let a = load(image, source);
    let c = load(image, adjustment);
    let (value, rdx) = match wrapper {
        Wrapper::Single => (next(a, c), correction),
        Wrapper::Repeated { raw_count } => (repeated_value(a, c, raw_count), 0),
    };
    for i in 0..6 {
        image[dest + 8 * i..dest + 8 * i + 8].copy_from_slice(&value[i].to_le_bytes());
    }
    Some(Registers {
        rax: value[2] & LOW,
        rdx,
        rsi: value[5] & LOW,
        rcx: correction,
        rdi: destination,
        r8: value[0],
        r9: value[1],
        r10: value[2],
        r11: value[3],
    })
}
