#![no_std]
//! Three complete node94 twelve-word arithmetic helpers, as a safe image projection.
//!
//! Arbitrary data aliases are supported. Original stack/control storage must be
//! disjoint from this stable, nonwrapping image. `None` is a new atomic refusal,
//! not an original return or memory-fault model. See the evidence packet proof.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Member {
    AddSaved,
    SubSaved,
    SubRaw,
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
    let offset = usize::try_from(address.checked_sub(base)?).ok()?;
    (offset.checked_add(width)? <= length).then_some(offset)
}

fn read(image: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(image[at..at + 8].try_into().unwrap())
}

fn write(image: &mut [u8], at: usize, value: u64) {
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn arithmetic(a: u64, b: u64, carry: bool, add: bool) -> (u64, bool) {
    if add {
        let wide = u128::from(a) + u128::from(b) + u128::from(carry);
        (wide as u64, wide >> 64 != 0)
    } else {
        let (value, first) = a.overflowing_sub(b);
        let (value, second) = value.overflowing_sub(u64::from(carry));
        (value, first || second)
    }
}

/// Update the 96-byte destination and return the observed GP register values.
/// `saved` supplies entry RBX/RBP/R12/R13/R14/R15, restored by saved variants.
/// RDI and RCX retain their input addresses; flags and original ABI are excluded.
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
) -> Option<Registers> {
    if u128::from(base) + image.len() as u128 > (1_u128 << 64) {
        return None;
    }
    let a_start = span(base, image.len(), a_address, 96)?;
    let b_start = span(base, image.len(), b_address, 96)?;
    let m_start = span(base, image.len(), correction_address, 48)?;
    let output = span(base, image.len(), destination, 96)?;
    let a: [u64; 12] = core::array::from_fn(|i| read(image, a_start + 8 * i));
    let add = member == Member::AddSaved;
    let mut state = [0_u64; 12];
    let mut carry = false;
    for i in 0..6 {
        (state[i], carry) = arithmetic(a[i], read(image, b_start + 8 * i), carry, add);
    }
    let order = if add {
        [0, 1, 2, 4, 3, 5]
    } else {
        [0, 1, 2, 3, 4, 5]
    };
    let mut correction = [0_u64; 6];
    for i in 0..6 {
        write(image, output + 8 * order[i], state[order[i]]);
        (state[6 + i], carry) = arithmetic(a[6 + i], read(image, b_start + 48 + 8 * i), carry, add);
        if !add {
            correction[i] = read(image, m_start + 8 * i);
        }
    }
    if add {
        correction = core::array::from_fn(|i| read(image, m_start + 8 * i));
    }
    let original_high: [u64; 6] = core::array::from_fn(|i| state[6 + i]);
    let mut upper = original_high;
    let rdx;
    let auxiliary;
    if add {
        let mut borrow = false;
        for i in 0..6 {
            (upper[i], borrow) = arithmetic(upper[i], correction[i], borrow, false);
        }
        rdx = 0_u64
            .wrapping_sub(u64::from(carry))
            .wrapping_sub(u64::from(borrow));
        if !carry && borrow {
            upper = original_high;
        }
        auxiliary = [
            original_high[0],
            original_high[1],
            original_high[2],
            original_high[3],
        ];
    } else {
        rdx = 0_u64.wrapping_sub(u64::from(carry));
        for word in &mut correction {
            *word &= rdx;
        }
        let mut overflow = false;
        for i in 0..6 {
            (upper[i], overflow) = arithmetic(upper[i], correction[i], overflow, true);
        }
        auxiliary = [correction[0], correction[1], correction[2], correction[3]];
    }
    for (i, word) in upper.iter().enumerate() {
        write(image, output + 48 + 8 * i, *word);
    }
    let callee = if member == Member::SubRaw {
        [
            upper[3],
            upper[4],
            correction[4],
            correction[5],
            upper[0],
            upper[1],
        ]
    } else {
        saved
    };
    Some(Registers {
        rax: upper[2],
        rdx,
        rsi: upper[5],
        r8_to_r11: auxiliary,
        callee,
    })
}
