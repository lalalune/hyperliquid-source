#![no_std]
#![forbid(unsafe_code)]
//! Snapshot-based byte reversal within eight four-byte lanes of node94 data.

/// A required range is unavailable; the entire image remains unchanged.
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

/// Reverse bytes within each of eight four-byte lanes, preserving entry RAX.
///
/// `image` is one nonwrapping abstract address interval beginning at `base`.
/// Complete nonwrapping 32-byte source and destination ranges must fit in it.
/// They may overlap at any byte displacement. Every source byte is sampled
/// before any destination store. Only destination bytes may change.
///
/// The return value projects the native unchanged RAX from `entry_rax`; it
/// does not identify a source-level return contract. Native code/control must
/// be valid and disjoint from writable data. Faults, MMIO, concurrency, flags,
/// other scratch registers, access traces and pointer ABI are not projected.
pub fn reverse_lanes(
    image: &mut [u8],
    base: u64,
    source: u64,
    destination: u64,
    entry_rax: u64,
) -> Result<u64, Unavailable> {
    if u128::from(base) + image.len() as u128 > (1_u128 << 64) {
        return Err(Unavailable);
    }
    let s = span(image, base, source, 32)?;
    let d = span(image, base, destination, 32)?;
    let before: [u8; 32] = image[s..s + 32].try_into().unwrap();
    for lane in 0..8 {
        let offset = lane * 4;
        let word = u32::from_le_bytes(before[offset..offset + 4].try_into().unwrap());
        image[d + offset..d + offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(entry_rax)
}
