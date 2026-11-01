#![no_std]
#![forbid(unsafe_code)]

/// Numeric values left in the three claimed native registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
    pub rcx: u64,
}

/// The required ordinary-memory spans do not fit the supplied image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn offset(image: &[u8], base: u64, address: u64, width: usize) -> Result<usize, Unavailable> {
    let index =
        usize::try_from(address.checked_sub(base).ok_or(Unavailable)?).map_err(|_| Unavailable)?;
    let end = index.checked_add(width).ok_or(Unavailable)?;
    if end > image.len() {
        return Err(Unavailable);
    }
    Ok(index)
}

fn read_words<const N: usize>(image: &[u8], start: usize) -> [u64; N] {
    core::array::from_fn(|i| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&image[start + i * 8..start + i * 8 + 8]);
        u64::from_le_bytes(bytes)
    })
}

fn write_words<const N: usize>(image: &mut [u8], start: usize, words: [u64; N]) {
    for (i, word) in words.into_iter().enumerate() {
        image[start + i * 8..start + i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
}

fn negate_if<const N: usize>(mut words: [u64; N], negative: bool) -> [u64; N] {
    if negative {
        let mut carry = 1u128;
        for word in &mut words {
            let sum = u128::from(!*word) + carry;
            *word = sum as u64;
            carry = sum >> 64;
        }
    }
    words
}

fn multiply<const N: usize>(words: [u64; N], scalar: u64) -> ([u64; N], u64) {
    let mut output = [0; N];
    let mut carry = 0u128;
    for (i, word) in words.into_iter().enumerate() {
        let product = u128::from(word) * u128::from(scalar) + carry;
        output[i] = product as u64;
        carry = product >> 64;
    }
    (output, carry as u64)
}

fn contribution(words: [u64; 4], scalar: u64) -> [u64; 5] {
    let negative = scalar >> 63 != 0;
    let magnitude = if negative {
        scalar.wrapping_neg()
    } else {
        scalar
    };
    let adjusted = negate_if(words, negative);
    let (low, carry) = multiply(adjusted, magnitude);
    // The native four-word negation discards its carry. In particular, a
    // negative scalar with a zero operand still retains this top correction.
    let top = carry.wrapping_sub(if negative { magnitude } else { 0 });
    [low[0], low[1], low[2], low[3], top]
}

/// Apply node94 ELF VA `0x565eaa0..0x565ec0b` to an ordinary-memory image.
///
/// Source is 64 bytes and destination is 32 bytes. Both spans and the image
/// must be nonwrapping. Arbitrary partial/unaligned aliases are supported:
/// the scalar words are stored first, and both operands see those stores.
/// All scalar/operand bits are admitted, including signed minima and zero.
///
/// Admission failure leaves the image unchanged. This claims destination
/// bytes and numeric RAX/RDX/RCX, excluding native faults, MMIO, concurrency,
/// code/control aliases, other registers and the original calling convention.
pub fn normalize(
    image: &mut [u8],
    base: u64,
    source: u64,
    destination: u64,
    x: u64,
    y: u64,
) -> Result<Registers, Unavailable> {
    if u128::from(base) + image.len() as u128 > (1u128 << 64) {
        return Err(Unavailable);
    }
    let source = offset(image, base, source, 64)?;
    let destination = offset(image, base, destination, 32)?;
    write_words(image, destination, [x, y]);
    // No target stores occur between its two operand loads, so this single
    // post-store snapshot preserves their values for every admitted alias.
    let words = read_words::<8>(image, source);
    let a = contribution([words[0], words[1], words[2], words[3]], x);
    let b = contribution([words[4], words[5], words[6], words[7]], y);
    let mut sum = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..5 {
        let total = u128::from(a[i]) + u128::from(b[i]) + carry;
        sum[i] = total as u64;
        carry = total >> 64;
    }
    let negative = sum[4] >> 63 != 0;
    let shifted: [u64; 4] = core::array::from_fn(|i| (sum[i] >> 31) | (sum[i + 1] << 33));
    let output = negate_if(shifted, negative);
    write_words(image, destination, output);
    Ok(Registers {
        rax: u64::from(negative),
        rdx: if negative { x.wrapping_neg() } else { x },
        rcx: if negative { y.wrapping_neg() } else { y },
    })
}
