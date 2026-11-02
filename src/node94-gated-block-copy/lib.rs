#![no_std]
#![forbid(unsafe_code)]
//! Safe image projection of node94 ELF VA 0x4ff8b30..0x4ff8b9c.

/// An actually accessed range is not available in the supplied image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

fn span(
    image_len: usize,
    base: usize,
    displacement: usize,
    size: usize,
) -> Result<usize, Unavailable> {
    let start = base.checked_add(displacement).ok_or(Unavailable)?;
    let end = start.checked_add(size).ok_or(Unavailable)?;
    if end > image_len {
        return Err(Unavailable);
    }
    Ok(start)
}

/// Select and copy 48 bytes, allowing every overlap within one memory image.
///
/// `flag == 0` selects source+344 without reading the index. Otherwise the
/// little-endian i32 at index_source+20 is decremented with wrapping arithmetic.
/// If it is at most `bound` and source+416 is nonzero, source+392 is selected.
/// The gate is read only when the first two tests pass. All selected bytes are
/// snapshotted before any write, including when the destination aliases them.
///
/// Returns the destination offset, representing the target's raw RAX pointer.
/// An unavailable used range returns an error without changing any byte.
/// This is a checked slice projection, not a native pointer/ABI or fault model.
pub fn copy_block(
    image: &mut [u8],
    destination: usize,
    source: usize,
    index_source: usize,
    bound: i32,
    flag: u8,
) -> Result<usize, Unavailable> {
    let mut displacement = 344;
    if flag != 0 {
        let index = span(image.len(), index_source, 20, 4)?;
        let field = i32::from_le_bytes(image[index..index + 4].try_into().unwrap());
        if field.wrapping_sub(1) <= bound {
            let gate = span(image.len(), source, 416, 1)?;
            if image[gate] != 0 {
                displacement = 392;
            }
        }
    }
    let selected = span(image.len(), source, displacement, 48)?;
    let output = span(image.len(), destination, 0, 48)?;
    let mut snapshot = [0_u8; 48];
    snapshot.copy_from_slice(&image[selected..selected + 48]);
    image[output..output + 48].copy_from_slice(&snapshot);
    Ok(destination)
}
