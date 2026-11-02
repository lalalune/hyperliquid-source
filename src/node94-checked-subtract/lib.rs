#![no_std]
#![forbid(unsafe_code)]
//! Final-image and raw-RAX projection of node94 0x2760a10..0x2760a67.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn span(image: &[u8], base: u64, address: u64, size: usize) -> Result<usize, Unavailable> {
    let start =
        usize::try_from(address.checked_sub(base).ok_or(Unavailable)?).map_err(|_| Unavailable)?;
    if start.checked_add(size).ok_or(Unavailable)? > image.len() {
        return Err(Unavailable);
    }
    Ok(start)
}

/// Subtract in place, then conditionally copy the difference and store a flag.
///
/// Addresses are abstract u64 values over one nonwrapping image. Both 32-byte
/// operands may overlap at any byte displacement. Right words observe preceding
/// lower-left stores. All left bytes are rewritten on success AND failure.
/// Success snapshots/copies 32 bytes to output+8; the final output qword is the
/// 0/1 flag, also returned as complete native RAX. Output may alias either input.
/// Only an 8-byte output is required on failure, 40 bytes on success.
///
/// Required ranges are checked before actual image writes; refusals preserve the
/// whole image. This is a final-state projection, not the native pointer ABI or
/// physical access trace. Wrapped operand/output ranges, native faults, MMIO,
/// concurrent mutation and instruction/control storage aliases are excluded.
pub fn subtract(
    image: &mut [u8],
    base: u64,
    left: u64,
    right: u64,
    output: u64,
) -> Result<u64, Unavailable> {
    if let Some(last) = image.len().checked_sub(1) {
        base.checked_add(u64::try_from(last).map_err(|_| Unavailable)?)
            .ok_or(Unavailable)?;
    }
    let a = span(image, base, left, 32)?;
    let b = span(image, base, right, 32)?;
    let o = span(image, base, output, 8)?;
    let mut planned: [u8; 32] = image[a..a + 32].try_into().unwrap();
    let mut borrow = false;
    for limb in 0..4 {
        let mut right_bytes = [0_u8; 8];
        for (j, byte) in right_bytes.iter_mut().enumerate() {
            let position = b + 8 * limb + j;
            *byte = if position >= a && position < a + 32 {
                planned[position - a]
            } else {
                image[position]
            };
        }
        let x = u64::from_le_bytes(planned[8 * limb..8 * limb + 8].try_into().unwrap());
        let y = u64::from_le_bytes(right_bytes);
        let (difference, first_borrow) = x.overflowing_sub(y);
        let (difference, extra_borrow) = difference.overflowing_sub(u64::from(borrow));
        borrow = first_borrow || extra_borrow;
        planned[8 * limb..8 * limb + 8].copy_from_slice(&difference.to_le_bytes());
    }
    let success = !borrow;
    if success {
        span(image, base, output, 40)?;
    }
    image[a..a + 32].copy_from_slice(&planned);
    if success {
        image[o + 24..o + 40].copy_from_slice(&planned[16..32]);
        image[o + 8..o + 24].copy_from_slice(&planned[..16]);
    }
    let flag = u64::from(success);
    image[o..o + 8].copy_from_slice(&flag.to_le_bytes());
    Ok(flag)
}
