#![no_std]
//! Numeric byte-image projection of four complete node94 repeated-doubling entries.
//! Every raw operand/count is admitted when the required image spans are present.
//! See the packet proof for stable-memory, control-storage and original ABI limits.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Member {
    PreparedStep,
    Three,
    Counted,
    PairThree,
}

/// General registers except RSP. `callee` is RBX,RBP,R12,R13,R14,R15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rcx: u64,
    pub rdi: u64,
    pub r8_to_r11: [u64; 4],
    pub callee: [u64; 6],
}

type Words = [u64; 6];

fn subtract(a: Words, b: Words) -> (Words, bool) {
    let mut result = [0; 6];
    let mut borrow = false;
    for i in 0..6 {
        let (difference, first) = a[i].overflowing_sub(b[i]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        result[i] = difference;
        borrow = first || second;
    }
    (result, borrow)
}

fn add(a: Words, b: Words) -> Words {
    let mut result = [0; 6];
    let mut carry = 0_u128;
    for i in 0..6 {
        let sum = u128::from(a[i]) + u128::from(b[i]) + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }
    result
}

fn step(x: Words, modulus: Words) -> (Words, Words, u64) {
    let mut doubled = [0; 6];
    let mut carry = 0;
    for i in 0..6 {
        doubled[i] = (x[i] << 1) | carry;
        carry = x[i] >> 63;
    }
    let (difference, borrow) = subtract(doubled, modulus);
    let result = if carry != 0 || !borrow {
        difference
    } else {
        doubled
    };
    let mask = 0_u64.wrapping_sub(carry).wrapping_sub(u64::from(borrow));
    (result, doubled, mask)
}

// Precondition: both operands are below the nonzero modulus.
fn modular_add(a: Words, b: Words, modulus: Words) -> Words {
    let threshold = subtract(modulus, b).0;
    let (difference, borrow) = subtract(a, threshold);
    if borrow {
        add(a, b)
    } else {
        difference
    }
}

fn modular_multiply(a: Words, b: Words, modulus: Words) -> Words {
    let mut total = [0; 6];
    let mut term = a;
    for word in b {
        for bit in 0..64 {
            if (word >> bit) & 1 != 0 {
                total = modular_add(total, term, modulus);
            }
            term = modular_add(term, term, modulus);
        }
    }
    total
}

fn scale(mut x: Words, mut count: u64, modulus: Words) -> Words {
    let one = if modulus == [1, 0, 0, 0, 0, 0] {
        [0; 6]
    } else {
        [1, 0, 0, 0, 0, 0]
    };
    let mut factor = modular_add(one, one, modulus);
    while count != 0 {
        if count & 1 != 0 {
            x = modular_multiply(x, factor, modulus);
        }
        count >>= 1;
        factor = modular_multiply(factor, factor, modulus);
    }
    x
}

fn advance(mut x: Words, modulus: Words, count: u64) -> Words {
    let warmup = count.min(384);
    for _ in 0..warmup {
        x = step(x, modulus).0;
    }
    let remaining = count - warmup;
    // After 384 steps: fixed point M (also zero when M=0), or x<M with M>0.
    if remaining == 0 || x == modulus {
        return x;
    }
    scale(x, remaining, modulus)
}

fn evaluate(x: Words, modulus: Words, count: u64) -> (Words, Registers) {
    let previous = advance(x, modulus, count - 1);
    let (value, temporary, mask) = step(previous, modulus);
    let registers = Registers {
        rax: temporary[2],
        rdx: mask,
        rsi: temporary[5],
        rcx: 0,
        rdi: 0,
        r8_to_r11: [value[0], value[1], value[2], value[3]],
        callee: [
            temporary[3],
            temporary[4],
            value[4],
            value[5],
            temporary[0],
            temporary[1],
        ],
    };
    (value, registers)
}

fn span(base: u64, length: usize, address: u64, size: usize) -> Option<usize> {
    let offset = usize::try_from(address.checked_sub(base)?).ok()?;
    if offset.checked_add(size)? <= length {
        Some(offset)
    } else {
        None
    }
}

fn words(image: &[u8], start: usize) -> Words {
    core::array::from_fn(|i| {
        u64::from_le_bytes(image[start + 8 * i..start + 8 * i + 8].try_into().unwrap())
    })
}

fn store(image: &mut [u8], start: usize, value: Words) {
    for (i, word) in value.iter().enumerate() {
        image[start + 8 * i..start + 8 * i + 8].copy_from_slice(&word.to_le_bytes());
    }
}

/// `None` is this API's atomic refusal for an unavailable/nonwrapping image span.
/// It is not a recovered original return. `prepared` supplies incoming R8..R13
/// only for PreparedStep; `saved` supplies incoming RBX,RBP,R12,R13,R14,R15 for
/// the three saving wrappers. Counted uses low32(raw_count), with zero = 2^32.
/// M is stable within each block. PairThree rereads high A and M after low stores.
/// Data may alias arbitrarily; code and valid control/stack storage are disjoint.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    member: Member,
    image: &mut [u8],
    base: u64,
    a_address: u64,
    m_address: u64,
    destination: u64,
    raw_count: u64,
    saved: Words,
    prepared: Words,
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1_u128 << 64) {
        return None;
    }
    let m_start = span(base, image.len(), m_address, 48)?;
    let width = if member == Member::PairThree { 96 } else { 48 };
    let (a_start, output) = if member == Member::PreparedStep {
        (0, 0)
    } else {
        (
            span(base, image.len(), a_address, width)?,
            span(base, image.len(), destination, width)?,
        )
    };
    let x = if member == Member::PreparedStep {
        prepared
    } else {
        words(image, a_start)
    };
    let modulus = words(image, m_start);
    let count = match member {
        Member::PreparedStep => 1,
        Member::Counted => {
            let low = u64::from(raw_count as u32);
            if low == 0 {
                1_u64 << 32
            } else {
                low
            }
        }
        _ => 3,
    };
    let (value, mut registers) = evaluate(x, modulus, count);
    if member != Member::PreparedStep {
        store(image, output, value);
    }
    if member == Member::PairThree {
        let high = words(image, a_start + 48);
        let live_modulus = words(image, m_start);
        let (value, high_registers) = evaluate(high, live_modulus, 3);
        store(image, output + 48, value);
        registers = high_registers;
    }
    registers.rcx = m_address;
    registers.rdi = destination;
    if member != Member::PreparedStep {
        registers.callee = saved;
    }
    if member == Member::Counted {
        registers.rdx = 0;
    }
    Some(registers)
}
