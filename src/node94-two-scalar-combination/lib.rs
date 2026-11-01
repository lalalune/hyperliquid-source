#![no_std]
#![forbid(unsafe_code)]

/// Numeric values left in the two claimed native registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
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

/// Apply node94 ELF VA `0x565e7a0..0x565e956` to one ordinary-memory image.
///
/// Source covers 104 bytes; destination covers 64 bytes. Both spans and the
/// image must be nonwrapping numeric ranges. Any partial or unaligned alias
/// between the spans is supported: four product words are stored before the
/// later eight source words are read. All scalar and source-word bits are
/// admitted, including signed minima and noncanonical fifth words.
///
/// Failure leaves the image unchanged. The projection excludes native faults,
/// MMIO, concurrency, code/control-memory aliases and the original register ABI.
/// It claims destination bytes and the numeric RAX/RDX values only.
pub fn combine(
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
    // Every address is fixed by source/destination; no loaded value changes
    // later addresses. Validate both complete spans before the first store.
    let source = offset(image, base, source, 104)?;
    let destination = offset(image, base, destination, 64)?;
    let x_negative = x >> 63 != 0;
    let magnitude_x = if x_negative { x.wrapping_neg() } else { x };
    let a = negate_if(read_words::<5>(image, source), x_negative);
    let (low, carry) = multiply([a[0], a[1], a[2], a[3]], magnitude_x);
    let top = carry.wrapping_sub(a[4] & magnitude_x);
    write_words(image, destination, low);

    // This read intentionally sees the preceding four stores on aliases.
    let y_negative = y >> 63 != 0;
    let magnitude_y = if y_negative { y.wrapping_neg() } else { y };
    let b = negate_if(read_words::<8>(image, source + 40), y_negative);
    let (mut result, high) = multiply(b, magnitude_y);
    let rax = b[7].wrapping_mul(magnitude_y);
    // The final native MUL is signed IMUL. Its low half is unchanged; its
    // high half differs by each operand's sign correction modulo 2^64.
    let rdx = high
        .wrapping_sub(if b[7] >> 63 != 0 { magnitude_y } else { 0 })
        .wrapping_sub(if magnitude_y >> 63 != 0 { b[7] } else { 0 });
    let extension = if top >> 63 != 0 { u64::MAX } else { 0 };
    let addend = [
        low[0], low[1], low[2], low[3], top, extension, extension, extension,
    ];
    let mut carry = 0u128;
    for i in 0..8 {
        let sum = u128::from(result[i]) + u128::from(addend[i]) + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }
    write_words(image, destination, result);
    Ok(Registers { rax, rdx })
}
