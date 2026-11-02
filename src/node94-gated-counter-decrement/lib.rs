#![no_std]
#![forbid(unsafe_code)]
//! Safe image projection of node94's five-pair gate and counter decrement.
//! See README.md and the evidence packet for the admitted memory domain.

/// A required access is outside the nonwrapping image; the image is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn span(image: &[u8], base: u64, address: u64, size: usize) -> Result<usize, Unavailable> {
    let offset =
        usize::try_from(address.checked_sub(base).ok_or(Unavailable)?).map_err(|_| Unavailable)?;
    if offset.checked_add(size).ok_or(Unavailable)? > image.len() {
        return Err(Unavailable);
    }
    Ok(offset)
}

fn qword(image: &[u8], base: u64, address: u64) -> Result<u64, Unavailable> {
    let offset = span(image, base, address, 8)?;
    Ok(u64::from_le_bytes(
        image[offset..offset + 8].try_into().unwrap(),
    ))
}

/// Compare five qword pairs in order, then conditionally decrement one dword.
///
/// `base` is the abstract address of `image[0]`; the entire image must fit in
/// the u64 address space. Field additions wrap modulo 2^64. Only accesses on
/// the chosen path need be mapped. Arbitrary aliases among data fields are
/// allowed. On a mismatch return the loaded inner pointer; after a decrement
/// return the owner pointer loaded before the store (the full raw RAX value).
///
/// This projects ordinary data memory, excluding control-stack/data aliases,
/// concurrent changes, MMIO, faults, executable memory and pointer-ABI claims.
/// The bound helper reads no argument memory and has an ordinary return.
pub fn decrement_if_equal(image: &mut [u8], base: u64, outer: u64) -> Result<u64, Unavailable> {
    if u128::from(base) + image.len() as u128 > (1_u128 << 64) {
        return Err(Unavailable);
    }
    let inner = qword(image, base, outer)?;
    for offset in [8, 56, 104, 128, 176] {
        let first = qword(image, base, inner.wrapping_add(offset))?;
        let second = qword(image, base, inner.wrapping_add(offset + 8))?;
        if first != second {
            return Ok(inner);
        }
    }
    // The only callee is the complete five-byte `endbr64; ret` body.
    // With disjoint control storage, the native owner reload observes the
    // same value; neither the owner itself nor owner+0x700 needs mapping.
    let owner = qword(image, base, outer.wrapping_add(8))?;
    let position = span(image, base, owner.wrapping_add(5276), 4)?;
    let counter = u32::from_le_bytes(image[position..position + 4].try_into().unwrap());
    image[position..position + 4].copy_from_slice(&counter.wrapping_sub(1).to_le_bytes());
    Ok(owner)
}
