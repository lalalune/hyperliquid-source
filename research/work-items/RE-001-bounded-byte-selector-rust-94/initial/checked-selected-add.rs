#![no_std]
#![forbid(unsafe_code)]
//! Safe data-image projections of node94 0x4ff8ac0 and its caller 0x5004e70.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn image_fits(image: &[u8], base: u64) -> Result<(), Unavailable> {
    if let Some(last) = image.len().checked_sub(1) {
        base.checked_add(u64::try_from(last).map_err(|_| Unavailable)?)
            .ok_or(Unavailable)?;
    }
    Ok(())
}

fn span(
    image: &[u8],
    base: u64,
    address: u64,
    displacement: u64,
    size: usize,
) -> Result<usize, Unavailable> {
    let absolute = address.checked_add(displacement).ok_or(Unavailable)?;
    let relative = absolute.checked_sub(base).ok_or(Unavailable)?;
    let start = usize::try_from(relative).map_err(|_| Unavailable)?;
    if start.checked_add(size).ok_or(Unavailable)? > image.len() {
        return Err(Unavailable);
    }
    Ok(start)
}
fn word32(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
}
fn word64(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap())
}

/// Return the selected byte; successful native RAX is exactly its zero extension.
///
/// Addresses are abstract values over `image`, never host pointers. Disabled
/// selection reads nothing. Other paths require only the fields/byte they use.
/// The relative index and span cap retain signed, wrapping low32 arithmetic;
/// this function does not assume the stored pointers delimit a valid array.
/// Fixed field addresses and the image may not wrap. Computed byte-address
/// addition wraps, then the actual byte must fit. Native faults, MMIO, concurrent
/// mutation, stack/control aliases and the original pointer ABI are excluded.
pub fn select_byte(
    image: &[u8],
    base: u64,
    inner: u64,
    context: u64,
    index: u32,
    bound: u32,
    enabled: u8,
) -> Result<u8, Unavailable> {
    if enabled == 0 {
        return Ok(0);
    }
    image_fits(image, base)?;
    let cached = image[span(image, base, context, 340, 1)?];
    if cached != 255 {
        let field = word32(image, span(image, base, inner, 20, 4)?);
        if (field.wrapping_sub(1) as i32) <= index as i32 {
            return Ok(cached);
        }
    }
    let high = word64(image, span(image, base, context, 464, 8)?);
    let low = word64(image, span(image, base, context, 456, 8)?);
    if high == low {
        return Ok(image[span(image, base, context, 339, 1)?]);
    }
    let address = if index == 0 {
        low
    } else {
        let relative = index.wrapping_sub(bound).wrapping_add(1) as i32;
        let last = (high.wrapping_sub(low) as u32).wrapping_sub(1) as i32;
        let step = relative.min(last).max(0) as u64;
        low.checked_add(step).ok_or(Unavailable)?
    };
    Ok(image[span(image, base, address, 0, 1)?])
}

/// Close the actual wrapper call and return its complete 0/1 RAX relation.
///
/// The bound at inner+2800 is eagerly required, even when the selector would not
/// use it. The comparison byte at object+4116 is read after successful selection.
/// This API never writes the image. Missing used ranges return `Unavailable`.
pub fn matches_stored(image: &[u8], base: u64, object: u64) -> Result<bool, Unavailable> {
    image_fits(image, base)?;
    let inner = word64(image, span(image, base, object, 0, 8)?);
    let index = word32(image, span(image, base, object, 8, 4)?);
    let bound = word32(image, span(image, base, inner, 2800, 4)?);
    let context = object.checked_add(904).ok_or(Unavailable)?;
    let selected = select_byte(image, base, inner, context, index, bound, 1)?;
    let stored = image[span(image, base, object, 4116, 1)?];
    Ok(selected == stored)
}
