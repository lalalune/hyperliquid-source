//! Complete scalar node94 [0x565b800,0x565ba10), as a safe value/image projection.
//! Native pointer ABI, flags, return control, faults and concurrent effects are excluded.
#![no_std]
#![forbid(unsafe_code)]

/// All fourteen written GP observations at return; RDI is unchanged and excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Square {
    pub words: [u64; 12],
    pub registers: Registers,
}

fn add_product(words: &mut [u64; 12], index: usize, product: u128) {
    let low = words[index] as u128 + product as u64 as u128;
    words[index] = low as u64;
    let high = words[index + 1] as u128 + (product >> 64) + (low >> 64);
    words[index + 1] = high as u64;
    let mut carry = (high >> 64) as u64;
    for word in &mut words[index + 2..] {
        let (value, next) = word.overflowing_add(carry);
        *word = value;
        carry = next as u64;
    }
}

/// Full 384-to-768-bit square and exact auxiliary observations for every input word.
pub fn square(input: [u64; 6]) -> Square {
    let mut cross = [0; 12];
    let mut r8 = 0;
    for i in 0..6 {
        if i == 3 {
            r8 = ((input[3] as u128 * input[4] as u128 + cross[7] as u128) >> 64) as u64;
        }
        for j in i + 1..6 {
            add_product(&mut cross, i + j, input[i] as u128 * input[j] as u128);
        }
    }
    let mut words = [0; 12];
    let mut incoming = [0; 6];
    let mut low_diagonal_plus_carry = [0; 6];
    let mut carry = 0u128;
    for i in 0..6 {
        let diagonal = input[i] as u128 * input[i] as u128;
        incoming[i] = carry as u64;
        low_diagonal_plus_carry[i] = (diagonal as u64).wrapping_add(carry as u64);
        let low = 2 * cross[2 * i] as u128 + diagonal as u64 as u128 + carry;
        words[2 * i] = low as u64;
        let high = 2 * cross[2 * i + 1] as u128 + (diagonal >> 64) + (low >> 64);
        words[2 * i + 1] = high as u64;
        carry = high >> 64;
    }
    Square {
        words,
        registers: Registers {
            rax: words[10],
            rbx: words[9],
            rcx: words[8],
            rdx: words[11],
            rbp: cross[10].wrapping_mul(2),
            rsi: input[5],
            r8,
            r9: low_diagonal_plus_carry[2],
            r10: words[2],
            r11: low_diagonal_plus_carry[3],
            r12: low_diagonal_plus_carry[4],
            r13: incoming[5],
            r14: words[6],
            r15: words[7],
        },
    }
}

fn offset(image: &[u8], base: u64, address: u64, width: usize) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    if start.checked_add(width)? > image.len() {
        return None;
    }
    Some(start)
}

/// Snapshot input48 before writing output96; all data aliases and byte alignments are admitted.
/// Ordinary stable data must exclude native return/control storage. Invalid spans refuse unchanged.
pub fn apply(image: &mut [u8], base: u64, input: u64, destination: u64) -> Option<Square> {
    if base as u128 + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let source = offset(image, base, input, 48)?;
    let target = offset(image, base, destination, 96)?;
    let mut snapshot = [0; 6];
    for i in 0..6 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&image[source + i * 8..source + i * 8 + 8]);
        snapshot[i] = u64::from_le_bytes(bytes);
    }
    let result = square(snapshot);
    for i in 0..12 {
        image[target + i * 8..target + i * 8 + 8].copy_from_slice(&result.words[i].to_le_bytes());
    }
    Some(result)
}
