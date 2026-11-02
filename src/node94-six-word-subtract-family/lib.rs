#![no_std]
#![forbid(unsafe_code)]
//! Complete node94 six-word subtraction/correction family as safe image values.
//! See the packet proof for entry aliases, stack premises and raw register order.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Member {
    Raw,
    Saved,
    HighFirstPair,
    Prepared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub r8_to_r11: [u64; 4],
    /// RBX, RBP, R12, R13, R14, R15 in that order.
    pub callee: [u64; 6],
}

fn span(base: u64, length: usize, address: u64, width: usize) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    (start.checked_add(width)? <= length).then_some(start)
}

fn words(image: &[u8], start: usize) -> [u64; 6] {
    core::array::from_fn(|i| {
        u64::from_le_bytes(image[start + 8 * i..start + 8 * i + 8].try_into().unwrap())
    })
}

fn execute(
    image: &mut [u8],
    a: [u64; 6],
    b_start: usize,
    m_start: usize,
    output: usize,
) -> Registers {
    let b = words(image, b_start);
    let correction = words(image, m_start);
    let mut result = [0_u64; 6];
    let mut borrow = false;
    for i in 0..6 {
        let (difference, first) = a[i].overflowing_sub(b[i]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        result[i] = difference;
        borrow = first || second;
    }
    let mask = 0_u64.wrapping_sub(u64::from(borrow));
    let masked: [u64; 6] = core::array::from_fn(|i| correction[i] & mask);
    let mut carry = 0_u128;
    for i in 0..6 {
        let total = u128::from(result[i]) + u128::from(masked[i]) + carry;
        result[i] = total as u64;
        carry = total >> 64;
    }
    for (i, value) in result.iter().enumerate() {
        image[output + 8 * i..output + 8 * i + 8].copy_from_slice(&value.to_le_bytes());
    }
    Registers {
        rax: masked[2],
        rdx: mask,
        rsi: masked[5],
        r8_to_r11: [result[0], result[1], result[2], result[3]],
        callee: [
            masked[3], masked[4], result[4], result[5], masked[0], masked[1],
        ],
    }
}

/// All data aliases are admitted within valid nonwrapping spans. A/B/D need
/// 48 bytes, or 96 for HighFirstPair; M always needs 48. Prepared does not read
/// or validate A: `prepared` supplies the actual incoming R8..R13 values.
/// `saved` supplies incoming RBX/RBP/R12/R13/R14/R15 only for Saved/HighFirstPair.
/// Original stack/control storage must be valid and disjoint from the image.
/// None is a new atomic bounds refusal, not a target return or fault model.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    member: Member,
    image: &mut [u8],
    base: u64,
    a_address: u64,
    b_address: u64,
    correction_address: u64,
    destination: u64,
    saved: [u64; 6],
    prepared: [u64; 6],
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1_u128 << 64) {
        return None;
    }
    let width = if member == Member::HighFirstPair {
        96
    } else {
        48
    };
    let a_start = if member == Member::Prepared {
        0
    } else {
        span(base, image.len(), a_address, width)?
    };
    let b_start = span(base, image.len(), b_address, width)?;
    let m_start = span(base, image.len(), correction_address, 48)?;
    let output = span(base, image.len(), destination, width)?;
    if member == Member::HighFirstPair {
        let high_a = words(image, a_start + 48);
        execute(image, high_a, b_start + 48, m_start, output + 48);
    }
    let a = if member == Member::Prepared {
        prepared
    } else {
        words(image, a_start)
    };
    let mut observed = execute(image, a, b_start, m_start, output);
    if matches!(member, Member::Saved | Member::HighFirstPair) {
        observed.callee = saved;
    }
    Some(observed)
}
