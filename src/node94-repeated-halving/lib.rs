//! Exact value/image projection of node #94 [0x565dbc0, 0x565dc5f).
//! All operand bits and raw count values are admitted. See PROOF.md for the
//! all-count acceleration and stable-memory/stack separation premises.
#![no_std]
#![forbid(unsafe_code)]

type Words = [u64; 4];
const ZERO: Words = [0; 4];
const TOP: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
}

fn add(a: Words, b: Words) -> (Words, bool) {
    let mut out = ZERO;
    let mut carry = 0_u128;
    for i in 0..4 {
        let sum = u128::from(a[i]) + u128::from(b[i]) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    (out, carry != 0)
}

fn subtract(a: Words, b: Words) -> (Words, bool) {
    let mut out = ZERO;
    let mut borrow = false;
    for i in 0..4 {
        let (v, first) = a[i].overflowing_sub(b[i]);
        let (v, second) = v.overflowing_sub(u64::from(borrow));
        out[i] = v;
        borrow = first || second;
    }
    (out, borrow)
}

fn shift_right(a: Words, high: bool) -> Words {
    [
        (a[0] >> 1) | (a[1] << 63),
        (a[1] >> 1) | (a[2] << 63),
        (a[2] >> 1) | (a[3] << 63),
        (a[3] >> 1) | (u64::from(high) << 63),
    ]
}

// Inputs are below the positive divisor, so at most one subtraction is needed.
fn add_mod(a: Words, b: Words, divisor: Words) -> Words {
    let (sum, carry) = add(a, b);
    let (difference, borrow) = subtract(sum, divisor);
    if carry || !borrow {
        difference
    } else {
        sum
    }
}

fn multiply_mod(mut a: Words, mut b: Words, divisor: Words) -> Words {
    let mut product = ZERO;
    while b != ZERO {
        if b[0] & 1 != 0 {
            product = add_mod(product, a, divisor);
        }
        b = shift_right(b, false);
        if b != ZERO {
            a = add_mod(a, a, divisor);
        }
    }
    product
}

/// Exact iteration count: zero low32 means 2^32 passes through the do-while loop.
fn value(mut x: Words, correction: Words, raw_count: u64) -> Words {
    let steps = if raw_count as u32 == 0 {
        1_u64 << 32
    } else {
        u64::from(raw_count as u32)
    };
    if x == ZERO {
        return ZERO;
    }
    let direct = steps.min(256);
    for _ in 0..direct {
        let selected = if x[0] & 1 != 0 { correction } else { ZERO };
        let (sum, carry) = add(x, selected);
        x = shift_right(sum, carry);
    }
    let mut remaining = steps - direct;
    if remaining == 0 || x == ZERO {
        return x;
    }
    // After 256 passes, a nonzero input is in 1..=divisor. M=0 has become zero.
    let divisor = if correction[0] & 1 == 0 {
        subtract(correction, [1, 0, 0, 0]).0
    } else {
        correction
    };
    if x == divisor {
        return divisor;
    }
    // For odd divisor >1, (divisor+1)/2 is the inverse of two modulo divisor.
    let mut power = add(shift_right(divisor, false), [1, 0, 0, 0]).0;
    while remaining != 0 {
        if remaining & 1 != 0 {
            x = multiply_mod(x, power, divisor);
        }
        remaining >>= 1;
        if remaining != 0 {
            power = multiply_mod(power, power, divisor);
        }
    }
    if x == ZERO {
        divisor
    } else {
        x
    }
}

fn load(image: &[u8], offset: usize) -> Words {
    let mut out = ZERO;
    for i in 0..4 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&image[offset + i * 8..offset + i * 8 + 8]);
        out[i] = u64::from_le_bytes(bytes);
    }
    out
}

/// Reconstruct all output bytes and seven unrestored written GP registers.
///
/// Original input/correction reads must be stable and valid. Data windows may
/// alias each other but must exclude original stack scratch and return control.
/// `None` is this API's unchanged-image range refusal, not a target result.
pub fn apply(
    image: &mut [u8],
    destination: usize,
    input: usize,
    correction: usize,
    raw_count: u64,
) -> Option<Registers> {
    for offset in [destination, input, correction] {
        if offset.checked_add(32)? > image.len() {
            return None;
        }
    }
    let x = load(image, input);
    let m = load(image, correction);
    let words = value(x, m, raw_count);
    for i in 0..4 {
        image[destination + i * 8..destination + i * 8 + 8]
            .copy_from_slice(&words[i].to_le_bytes());
    }
    Some(Registers {
        rax: words[3] & TOP,
        rdx: 0,
        rsi: words[2] & TOP,
        r8: words[0] & (TOP - 1),
        r9: words[1],
        r10: words[2],
        r11: words[3],
    })
}
