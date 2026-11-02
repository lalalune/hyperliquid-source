#![no_std]
#![forbid(unsafe_code)]

//! Checked readonly image projection of node94 `[0x50fa260,0x50fa2b2)`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registers {
    pub rax: u64,
    pub rdx: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    PrimaryFlag,
    StoredPair,
    SecondaryFlag,
    ComputedWords,
}

fn bytes(image: &[u8], base: u64, address: u64, width: usize) -> Option<&[u8]> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    image.get(start..end)
}

fn byte(image: &[u8], base: u64, address: u64) -> Option<u8> {
    Some(bytes(image, base, address, 1)?[0])
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes(image, base, address, 8)?.try_into().unwrap(),
    ))
}

/// Return full RAX and RDX from stable ordinary memory.
///
/// Byte j represents `image_base + j` in a nonwrapping numeric image.
/// Object-relative field addresses wrap before their reached spans are checked.
/// Only flag 1 selects the stored pair; that path skips all computed fields.
/// Refusals are new safe outcomes, not observations of original native faults.
/// Returned numbers are not dereferenced or validated as pointers.
pub fn select(image: &[u8], image_base: u64, object: u64) -> Result<Registers, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let primary =
        byte(image, image_base, object.wrapping_add(0x240)).ok_or(AccessError::PrimaryFlag)?;
    if primary == 1 {
        let rdx =
            word(image, image_base, object.wrapping_add(0x310)).ok_or(AccessError::StoredPair)?;
        let rax =
            word(image, image_base, object.wrapping_add(0x308)).ok_or(AccessError::StoredPair)?;
        return Ok(Registers { rax, rdx });
    }
    let secondary =
        byte(image, image_base, object.wrapping_add(0xd8)).ok_or(AccessError::SecondaryFlag)?;
    let span =
        word(image, image_base, object.wrapping_add(0xa8)).ok_or(AccessError::ComputedWords)?;
    let value =
        word(image, image_base, object.wrapping_add(0xa0)).ok_or(AccessError::ComputedWords)?;
    let adjusted = if secondary == 0 {
        span.wrapping_sub(8)
    } else {
        span
    };
    let limit =
        word(image, image_base, object.wrapping_add(0x300)).ok_or(AccessError::ComputedWords)?;
    let rax = value.wrapping_add(adjusted.wrapping_sub(limit));
    Ok(Registers { rax, rdx: limit })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_path_skips_unmapped_computed_fields() {
        let mut image = [0_u8; 216];
        image[0] = 1;
        image[200..208].copy_from_slice(&u64::MAX.to_le_bytes());
        image[208..216].copy_from_slice(&19_u64.to_le_bytes());
        assert_eq!(
            select(&image, 0, 0_u64.wrapping_sub(0x240)),
            Ok(Registers {
                rax: u64::MAX,
                rdx: 19
            })
        );
    }

    #[test]
    fn computed_path_wraps_and_skips_stored_fields() {
        let mut image = [0_u8; 0x308];
        image[0x240] = 2;
        image[0xa0..0xa8].copy_from_slice(&3_u64.to_le_bytes());
        image[0xa8..0xb0].copy_from_slice(&7_u64.to_le_bytes());
        image[0x300..0x308].copy_from_slice(&11_u64.to_le_bytes());
        assert_eq!(
            select(&image, 0, 0),
            Ok(Registers {
                rax: u64::MAX - 8,
                rdx: 11
            })
        );
    }

    #[test]
    fn exact_image_endpoint_is_admitted() {
        let mut image = [0_u8; 216];
        image[0] = 1;
        image[208..].copy_from_slice(&u64::MAX.to_le_bytes());
        let base = u64::MAX - 215;
        assert_eq!(
            select(&image, base, base.wrapping_sub(0x240)),
            Ok(Registers {
                rax: 0,
                rdx: u64::MAX
            })
        );
    }
}
