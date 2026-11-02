#![no_std]
#![forbid(unsafe_code)]
//! Checked image projection of the two complete node94 chained-field accessors.

use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    Signed32,
    Word64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    FirstPointer,
    SecondPointer,
    Value,
    Output,
}

fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image[span(image, base, address, 8)?].try_into().unwrap(),
    ))
}

/// Load the selected deep field, write one qword, and return complete native RAX.
///
/// Byte j represents numeric address image_base+j in a nonwrapping image.
/// Field addresses wrap before their complete reached spans are admitted.
/// Every read precedes the output write, so arbitrary data aliases are allowed.
/// Refusals are new safe outcomes and leave the entire image unchanged. Ordinary
/// stable valid memory is required for correspondence; native faults, MMIO,
/// concurrency, control/code aliases, ABI and access traces are excluded.
pub fn extract(
    field: Field,
    image: &mut [u8],
    image_base: u64,
    object: u64,
    output: u64,
) -> Result<u64, AccessError> {
    if let Some(last) = image.len().checked_sub(1) {
        image_base
            .checked_add(u64::try_from(last).map_err(|_| AccessError::ImageRange)?)
            .ok_or(AccessError::ImageRange)?;
    }
    let first =
        word(image, image_base, object.wrapping_add(0x788)).ok_or(AccessError::FirstPointer)?;
    let second =
        word(image, image_base, first.wrapping_add(0x30)).ok_or(AccessError::SecondPointer)?;
    let value = match field {
        Field::Signed32 => {
            let at =
                span(image, image_base, second.wrapping_add(0xb30), 4).ok_or(AccessError::Value)?;
            u32::from_le_bytes(image[at].try_into().unwrap()) as i32 as i64 as u64
        }
        Field::Word64 => {
            word(image, image_base, second.wrapping_add(0x1008)).ok_or(AccessError::Value)?
        }
    };
    let destination = span(image, image_base, output, 8).ok_or(AccessError::Output)?;
    image[destination].copy_from_slice(&value.to_le_bytes());
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> [u8; 136] {
        let mut image = [0_u8; 136];
        image[16..24].copy_from_slice(&16_u64.to_le_bytes());
        image[64..72].copy_from_slice(&128_u64.wrapping_sub(0xb30).to_le_bytes());
        image[128..132].copy_from_slice(&0x80000000_u32.to_le_bytes());
        image
    }

    #[test]
    fn signed_field_is_four_bytes_even_at_exact_end() {
        let mut image = setup();
        assert_eq!(
            extract(
                Field::Signed32,
                &mut image[..132],
                0,
                16_u64.wrapping_sub(0x788),
                24
            ),
            Ok(1)
        );
        assert_eq!(&image[24..32], &0xffffffff80000000_u64.to_le_bytes());
    }

    #[test]
    fn output_can_overwrite_a_previously_read_pointer() {
        let mut image = setup();
        assert_eq!(
            extract(
                Field::Signed32,
                &mut image,
                0,
                16_u64.wrapping_sub(0x788),
                16
            ),
            Ok(1)
        );
        assert_eq!(&image[16..24], &0xffffffff80000000_u64.to_le_bytes());
    }

    #[test]
    fn short_output_refusal_preserves_every_byte() {
        let mut image = setup();
        let before = image;
        assert_eq!(
            extract(
                Field::Signed32,
                &mut image,
                0,
                16_u64.wrapping_sub(0x788),
                129
            ),
            Err(AccessError::Output)
        );
        assert_eq!(image, before);
    }
}
