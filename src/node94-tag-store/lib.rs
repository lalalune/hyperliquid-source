#![no_std]
#![forbid(unsafe_code)]

//! Complete image/RAX projection of node94 `[0x5057700,0x505773d)`.

use core::ops::Range;

pub const LINKED_ADDRESS: u64 = 0x57592a0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    Source,
    Destination,
}

fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}

/// Apply the store selected by low32(tag), returning complete native RAX=0.
///
/// Byte j maps to image_base+j in a nonwrapping image. load_bias independently
/// gives the code's runtime bias; tag 0 stores its linked-address sum without
/// reading the pointed contents. Tag 1 stores source as an immediate u64; tag 2
/// reads a complete 16-byte snapshot before writing, allowing arbitrary overlap.
/// Other tags access neither source nor destination. New safe refusals are
/// atomic; original faults, ABI, control aliases and access traces are excluded.
pub fn store(
    image: &mut [u8],
    image_base: u64,
    load_bias: u64,
    destination: u64,
    source: u64,
    tag: u64,
) -> Result<u64, AccessError> {
    if let Some(last) = image.len().checked_sub(1) {
        image_base
            .checked_add(u64::try_from(last).map_err(|_| AccessError::ImageRange)?)
            .ok_or(AccessError::ImageRange)?;
    }
    match tag as u32 {
        0 => {
            let value = load_bias.wrapping_add(LINKED_ADDRESS);
            let to = span(image, image_base, destination, 8).ok_or(AccessError::Destination)?;
            image[to].copy_from_slice(&value.to_le_bytes());
        }
        1 => {
            let to = span(image, image_base, destination, 8).ok_or(AccessError::Destination)?;
            image[to].copy_from_slice(&source.to_le_bytes());
        }
        2 => {
            let from = span(image, image_base, source, 16).ok_or(AccessError::Source)?;
            let value: [u8; 16] = image[from].try_into().unwrap();
            let to = span(image, image_base, destination, 16).ok_or(AccessError::Destination)?;
            image[to].copy_from_slice(&value);
        }
        _ => {}
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_tag_bits_do_not_change_pointer_value_store() {
        let mut image = [0_u8; 8];
        assert_eq!(store(&mut image, 7, 19, 7, u64::MAX, 0x123400000001), Ok(0));
        assert_eq!(image, u64::MAX.to_le_bytes());
    }

    #[test]
    fn copy_uses_one_snapshot_for_partial_overlap() {
        let mut image = [0_u8; 20];
        for (i, b) in image.iter_mut().enumerate() {
            *b = i as u8;
        }
        let before = image;
        assert_eq!(store(&mut image, 0, 0, 1, 0, 2), Ok(0));
        assert_eq!(&image[1..17], &before[..16]);
    }

    #[test]
    fn refused_output_is_atomic_and_other_tags_skip_accesses() {
        let mut image = [31_u8; 16];
        let before = image;
        assert_eq!(
            store(&mut image, 0, 0, 1, 0, 2),
            Err(AccessError::Destination)
        );
        assert_eq!(image, before);
        assert_eq!(store(&mut [], 0, u64::MAX, u64::MAX, u64::MAX, 3), Ok(0));
    }
}
