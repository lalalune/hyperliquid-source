#![no_std]
#![forbid(unsafe_code)]
//! Safe image projection of node94 ELF VA 0x3290130..0x3290192.

/// A required address/range is unavailable without wrapping the image mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn span(
    len: usize,
    base: u64,
    address: u64,
    displacement: u64,
    size: usize,
) -> Result<usize, Unavailable> {
    let absolute = address.checked_add(displacement).ok_or(Unavailable)?;
    let relative = absolute.checked_sub(base).ok_or(Unavailable)?;
    let start = usize::try_from(relative).map_err(|_| Unavailable)?;
    let end = start.checked_add(size).ok_or(Unavailable)?;
    if end > len {
        return Err(Unavailable);
    }
    Ok(start)
}

fn qword(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
}

/// Update a selected link/slot and write tag 5 last, preserving every image alias.
///
/// `image` occupies abstract addresses starting at `base`; the other u64 values
/// are addresses in that model, never dereferenced host pointers. `owner+216`
/// contains the base whose field at +568 supplies the new link. A zero qword at
/// `state` selects displacement 16; otherwise displacement 0. The kind byte at
/// state+displacement+64 controls retained slot bytes: 16 for kinds 0..=4, 8 for
/// 16..=21, zero otherwise. The link is at +40, and the 16-byte slot at +48.
///
/// Every read is snapshotted before writes. The final byte at `output` is 5,
/// including when it aliases a restored slot or the link. Returns `output`,
/// corresponding to raw RAX. Missing used ranges return an error with no writes.
/// Native faults, volatile/concurrent memory and the original ABI are excluded.
pub fn restore(
    image: &mut [u8],
    base: u64,
    output: u64,
    owner: u64,
    state: u64,
) -> Result<u64, Unavailable> {
    if let Some(last) = image.len().checked_sub(1) {
        let last = u64::try_from(last).map_err(|_| Unavailable)?;
        base.checked_add(last).ok_or(Unavailable)?;
    }
    let owner_field = span(image.len(), base, owner, 216, 8)?;
    let selector_field = span(image.len(), base, state, 0, 8)?;
    let hop = qword(image, owner_field);
    let selector = qword(image, selector_field);
    let displacement = if selector == 0 { 16 } else { 0 };
    let kind_field = span(image.len(), base, state, displacement + 64, 1)?;
    let slot = span(image.len(), base, state, displacement + 48, 16)?;
    let link = span(image.len(), base, state, displacement + 40, 8)?;
    let hop_field = span(image.len(), base, hop, 568, 8)?;
    let tag = span(image.len(), base, output, 0, 1)?;
    let kind = image[kind_field];
    let old: [u8; 16] = image[slot..slot + 16].try_into().unwrap();
    let new_link: [u8; 8] = image[hop_field..hop_field + 8].try_into().unwrap();
    image[link..link + 8].copy_from_slice(&new_link);
    image[slot..slot + 16].fill(0);
    if (16..=21).contains(&kind) {
        image[slot..slot + 8].copy_from_slice(&old[..8]);
    } else if kind <= 4 {
        image[slot..slot + 16].copy_from_slice(&old);
    }
    image[tag] = 5;
    Ok(output)
}
