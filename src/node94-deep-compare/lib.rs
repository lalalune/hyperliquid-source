#![no_std]
#![forbid(unsafe_code)]

//! Raw RAX/RDX projection of node94 `[0x51c0c00,0x51c0c18)`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    FirstHop,
    SecondHop,
    FirstValue,
    SecondValue,
}

fn read(image: &[u8], base: u64, address: u64) -> Option<u64> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let bytes = image.get(start..start.checked_add(8)?)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// Compare second deep value below first, preserving RAX's upper 56 bits.
///
/// Image byte j represents `image_base + j` in one nonwrapping range.
/// All four field-address additions wrap before their qword ranges are checked.
/// Reads follow the captured order and may alias arbitrarily. Errors are new
/// safe refusals, not native fault observations. Ordinary stable target memory
/// and valid control storage are required for the numeric correspondence.
pub fn compare(
    image: &[u8],
    image_base: u64,
    first: u64,
    second: u64,
) -> Result<Registers, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let first_hop = read(image, image_base, first.wrapping_add(8)).ok_or(AccessError::FirstHop)?;
    let second_hop =
        read(image, image_base, second.wrapping_add(8)).ok_or(AccessError::SecondHop)?;
    let first_value =
        read(image, image_base, first_hop.wrapping_add(120)).ok_or(AccessError::FirstValue)?;
    let second_value =
        read(image, image_base, second_hop.wrapping_add(120)).ok_or(AccessError::SecondValue)?;
    Ok(Registers {
        rax: (first_value & !255_u64) | u64::from(second_value < first_value),
        rdx: second_hop,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_al_is_replaced() {
        let mut image = [0_u8; 160];
        image[8..16].copy_from_slice(&8_u64.to_le_bytes());
        image[24..32].copy_from_slice(&32_u64.to_le_bytes());
        image[128..136].copy_from_slice(&0x1234_u64.to_le_bytes());
        image[152..160].copy_from_slice(&0x1000_u64.to_le_bytes());
        assert_eq!(
            compare(&image, 0, 0, 16),
            Ok(Registers {
                rax: 0x1201,
                rdx: 32
            })
        );
    }

    #[test]
    fn wrapped_first_hop_and_equal_alias() {
        let mut image = [0_u8; 136];
        image[..8].copy_from_slice(&8_u64.to_le_bytes());
        image[128..136].copy_from_slice(&0x8000_0000_0000_00ff_u64.to_le_bytes());
        let object = u64::MAX - 7;
        assert_eq!(
            compare(&image, 0, object, object),
            Ok(Registers {
                rax: 0x8000_0000_0000_0000,
                rdx: 8
            })
        );
    }

    #[test]
    fn second_hop_admission_precedes_first_value() {
        let mut image = [0_u8; 16];
        image[8..16].fill(255);
        assert_eq!(compare(&image, 0, 0, 16), Err(AccessError::SecondHop));
    }
}
