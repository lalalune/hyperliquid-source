#![no_std]
#![forbid(unsafe_code)]
//! Safe image projection of node94 ELF VA 0x4fa90a0..0x4fa9109.

/// A selected field or qword is unavailable in the nonwrapping image.
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
    if start.checked_add(size).ok_or(Unavailable)? > len {
        return Err(Unavailable);
    }
    Ok(start)
}

fn pointer(image: &[u8], base: u64, table: u64, index: u64) -> Result<u64, Unavailable> {
    let (field, entry) = if index <= 31 {
        (264, index)
    } else {
        (272, index.wrapping_sub(32))
    };
    let offset = span(image.len(), base, table, field, 8)?;
    let table_base = u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
    let displacement = entry.wrapping_mul(8);
    Ok(table_base.wrapping_add(displacement))
}

/// Exchange selected qwords with the target's second-then-first store order.
///
/// Address values describe an abstract image; no host pointer is dereferenced.
/// Indices 0..=31 select each table's qword field at +264. Larger full u64
/// indices select +272 with index-32. Scaling by eight and adding the loaded
/// base wrap modulo 2^64, then each resulting eight-byte range must fit image.
///
/// Both table fields and both values are snapshotted before writes. For partial
/// overlap the first selected range has last-write priority. Returns its original
/// computed address, corresponding to raw RAX. Invalid used ranges return an
/// error without writes. Fixed table-field addresses and the image may not wrap.
/// Faults, MMIO/concurrency and the native pointer ABI are outside this projection.
pub fn swap_indexed(
    image: &mut [u8],
    base: u64,
    first_table: u64,
    first_index: u64,
    second_table: u64,
    second_index: u64,
) -> Result<u64, Unavailable> {
    if let Some(last) = image.len().checked_sub(1) {
        base.checked_add(u64::try_from(last).map_err(|_| Unavailable)?)
            .ok_or(Unavailable)?;
    }
    let first_address = pointer(image, base, first_table, second_index)?;
    let second_address = pointer(image, base, second_table, second_index)?;
    let first = span(image.len(), base, first_address, 0, 8)?;
    let second = span(image.len(), base, second_address, 0, 8)?;
    let first_value: [u8; 8] = image[first..first + 8].try_into().unwrap();
    let second_value: [u8; 8] = image[second..second + 8].try_into().unwrap();
    image[second..second + 8].copy_from_slice(&first_value);
    image[first..first + 8].copy_from_slice(&second_value);
    Ok(first_address)
}
