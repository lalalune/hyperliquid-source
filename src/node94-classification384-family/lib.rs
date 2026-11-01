//! Complete node94 six-word classification pair, as safe value/read-only image projections.
//! Original pointer ABI, control-stack effects, flags and fault behavior are excluded.
#![no_std]
#![forbid(unsafe_code)]

pub type Words = [u64; 6];

/// Eight final GP observations. RSI is unchanged; pair RBX/RBP are restored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observations {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
}

fn twice_minus(a: Words, correction: Words) -> (Words, u64) {
    let mut doubled = [0; 6];
    let mut carry = 0u128;
    for i in 0..6 {
        let total = (a[i] as u128) * 2 + carry;
        doubled[i] = total as u64;
        carry = total >> 64;
    }
    let mut difference = [0; 6];
    let mut borrow = false;
    for i in 0..6 {
        let (word, first) = doubled[i].overflowing_sub(correction[i]);
        let (word, second) = word.overflowing_sub(borrow as u64);
        difference[i] = word;
        borrow = first || second;
    }
    let high = (carry as u64).wrapping_sub(borrow as u64);
    (difference, (!high) & 2)
}

/// Complete [0x56573a0,0x5657402): parity plus twice-value comparison and raw difference.
/// Every operand word has its full u64 domain; no reduced-value premise applies.
pub fn classify(a: Words, correction: Words) -> Observations {
    let (difference, comparison) = twice_minus(a, correction);
    let parity = a[0] & 1;
    Observations {
        rax: comparison | parity,
        rcx: difference[4],
        rdx: difference[5],
        rdi: parity,
        r8: difference[0],
        r9: difference[1],
        r10: difference[2],
        r11: difference[3],
    }
}

/// Complete [0x5657420,0x5657531): zero-dependent selection from two six-word inputs.
/// The raw R8 is the low input's limb union, while RDI is the high input's full tag.
pub fn classify_pair(low: Words, high: Words, correction: Words) -> Observations {
    let high_result = classify(high, correction);
    let low_result = classify(low, correction);
    let low_union = low.into_iter().fold(0, |acc, word| acc | word);
    let high_union = high.into_iter().fold(0, |acc, word| acc | word);
    let parity = if low_union == 0 {
        high_result.rax & 1
    } else {
        low[0] & 1
    };
    let comparison = if high_union != 0 {
        high_result.rax & 2
    } else {
        low_result.rax & 2
    };
    Observations {
        rax: comparison | parity,
        rcx: low_result.rcx,
        rdx: low_result.rdx,
        rdi: high_result.rax,
        r8: low_union,
        r9: low_result.r9,
        r10: low_result.r10,
        r11: low_result.r11,
    }
}

fn offset(image: &[u8], base: u64, address: u64, width: usize) -> Option<usize> {
    if base as u128 + image.len() as u128 > (1u128 << 64) {
        return None;
    }
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    if start.checked_add(width)? > image.len() {
        return None;
    }
    Some(start)
}
fn load(image: &[u8], start: usize) -> Words {
    let mut words = [0; 6];
    for i in 0..6 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&image[start + i * 8..start + i * 8 + 8]);
        words[i] = u64::from_le_bytes(bytes);
    }
    words
}

/// Stable ordinary little-endian inputs may overlap at arbitrary byte offsets.
/// Both 48-byte spans are mandatory; refusal is a new safe-API policy, not a target fault.
pub fn read_single(image: &[u8], base: u64, input: u64, correction: u64) -> Option<Observations> {
    let a = offset(image, base, input, 48)?;
    let c = offset(image, base, correction, 48)?;
    Some(classify(load(image, a), load(image, c)))
}

/// Requires the whole 96-byte input and 48-byte correction, even when a block is zero.
/// Original control-stack storage must be disjoint from the supplied stable input memory.
pub fn read_pair(image: &[u8], base: u64, input: u64, correction: u64) -> Option<Observations> {
    let a = offset(image, base, input, 96)?;
    let c = offset(image, base, correction, 48)?;
    let high = load(image, a + 48);
    let correction = load(image, c);
    let low = load(image, a);
    Some(classify_pair(low, high, correction))
}
