//! Numeric and ordered-image projection of four node #94 correction leaves.
//!
//! All operand bits are admitted. Original reads must succeed and be stable;
//! operand/output windows may overlap each other but must not overlap the
//! original stack scratch or return-control storage. This safe byte-image API
//! does not reproduce that machine ABI, pointer faults, flags or racing memory.
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Variant {
    Add,
    Subtract,
    AddNonzero,
    SubtractNonzero,
}

/// The seven general-purpose registers overwritten without being restored.
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

fn add(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut result = [0; 4];
    let mut carry = 0_u128;
    for lane in 0..4 {
        let sum = u128::from(a[lane]) + u128::from(b[lane]) + carry;
        result[lane] = sum as u64;
        carry = sum >> 64;
    }
    (result, carry != 0)
}

fn subtract(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut result = [0; 4];
    let mut borrow = false;
    for lane in 0..4 {
        let (difference, first) = a[lane].overflowing_sub(b[lane]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        result[lane] = difference;
        borrow = first || second;
    }
    (result, borrow)
}

fn load(image: &[u8], offset: usize) -> [u64; 4] {
    let mut result = [0; 4];
    for lane in 0..4 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&image[offset + lane * 8..offset + lane * 8 + 8]);
        result[lane] = u64::from_le_bytes(bytes);
    }
    result
}

/// Apply one complete family member to an image of stable ordinary memory.
///
/// Each offset starts a 32-byte window. `None` is a new API refusal for an
/// out-of-image or overflowing range, with the image unchanged; it is not an
/// original target return. All input snapshots precede every output store.
pub fn apply(
    image: &mut [u8],
    destination: usize,
    left: usize,
    right: usize,
    correction: usize,
    variant: Variant,
) -> Option<Registers> {
    for offset in [destination, left, right, correction] {
        if offset.checked_add(32)? > image.len() {
            return None;
        }
    }
    let a = load(image, left);
    let b = load(image, right);
    let m = load(image, correction);
    let (words, mut rax, rdx, rsi) = if matches!(variant, Variant::Add | Variant::AddNonzero) {
        let (sum, carry) = add(a, b);
        let (difference, borrow) = subtract(sum, m);
        let words = if carry || !borrow { difference } else { sum };
        let mask = 0_u64
            .wrapping_sub(u64::from(carry))
            .wrapping_sub(u64::from(borrow));
        (words, sum[0], mask, sum[1])
    } else {
        let (difference, borrow) = subtract(a, b);
        let selected = if borrow { m } else { [0; 4] };
        let (words, _) = add(difference, selected);
        (
            words,
            selected[0],
            0_u64.wrapping_sub(u64::from(borrow)),
            selected[1],
        )
    };
    for lane in 0..4 {
        image[destination + lane * 8..destination + lane * 8 + 8]
            .copy_from_slice(&words[lane].to_le_bytes());
    }
    let mut r8 = words[0];
    let mut r10 = words[2];
    if matches!(variant, Variant::AddNonzero | Variant::SubtractNonzero) {
        r8 = words[0] | words[1] | words[2] | words[3];
        r10 = words[2] | words[3];
        rax = u64::from(r8 != 0);
    }
    Some(Registers {
        rax,
        rdx,
        rsi,
        r8,
        r9: words[1],
        r10,
        r11: words[3],
    })
}
