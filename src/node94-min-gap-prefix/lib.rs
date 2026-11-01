#![no_std]
#![forbid(unsafe_code)]

//! Checked image projection of node94 `[0x5430db0,0x5430e07)`.

use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    Lengths,
    Pointers,
    Bytes,
}

fn span(image: &[u8], base: u64, address: u64, width: u64) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(usize::try_from(width).ok()?)?;
    (end <= image.len()).then_some(start..end)
}

fn word(image: &[u8], base: u64, address: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image[span(image, base, address, 8)?].try_into().unwrap(),
    ))
}

/// Return full numeric RAX (0 or 1) under the documented memcmp premise.
///
/// Image byte j represents address `image_base + j` in a nonwrapping range.
/// Field addresses wrap before admission; reached byte spans must be complete.
/// Zero minimum length skips both pointer fields and payload ranges. Otherwise
/// payload admission occurs even when the final length ordering rejects.
/// This readonly API introduces safe refusals instead of original faults.
/// Correspondence assumes ordinary stable memory and standard normal-return
/// memcmp behavior (no writes; zero exactly when all compared bytes agree).
pub fn compare(image: &[u8], image_base: u64, a: u64, b: u64) -> Result<u64, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let b_length = word(image, image_base, b.wrapping_add(8)).ok_or(AccessError::Lengths)?;
    let a_length = word(image, image_base, a.wrapping_add(8)).ok_or(AccessError::Lengths)?;
    let n = a_length.min(b_length);
    if n == 0 {
        return Ok(u64::from(b_length == 0));
    }
    let b_pointer = word(image, image_base, b).ok_or(AccessError::Pointers)?;
    let a_pointer = word(image, image_base, a).ok_or(AccessError::Pointers)?;
    let left = span(image, image_base, a_pointer, n).ok_or(AccessError::Bytes)?;
    let right = span(image, image_base, b_pointer, n).ok_or(AccessError::Bytes)?;
    let same = image[left] == image[right];
    Ok(u64::from(b_length <= a_length && same))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(x: u64, y: u64) -> [u8; 64] {
        let mut image = [0_u8; 64];
        image[..8].copy_from_slice(&32_u64.to_le_bytes());
        image[8..16].copy_from_slice(&x.to_le_bytes());
        image[16..24].copy_from_slice(&40_u64.to_le_bytes());
        image[24..32].copy_from_slice(&y.to_le_bytes());
        image[32..35].copy_from_slice(b"a\0b");
        image[40..43].copy_from_slice(b"a\0c");
        image
    }

    #[test]
    fn comparison_includes_bytes_after_nul() {
        assert_eq!(compare(&setup(3, 3), 0, 0, 16), Ok(0));
        assert_eq!(compare(&setup(3, 2), 0, 0, 16), Ok(1));
    }

    #[test]
    fn zero_minimum_skips_unmapped_pointer_field() {
        let mut image = [0_u8; 24];
        image[16..24].copy_from_slice(&(1_u64 << 32).to_le_bytes());
        assert_eq!(compare(&image, 0, u64::MAX - 7, 8), Ok(0));
    }

    #[test]
    fn shorter_a_still_requires_both_payload_spans() {
        let mut image = setup(1, 2);
        image[..8].copy_from_slice(&100_u64.to_le_bytes());
        assert_eq!(compare(&image, 0, 0, 16), Err(AccessError::Bytes));
    }
}
