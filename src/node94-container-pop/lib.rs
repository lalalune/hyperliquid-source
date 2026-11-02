#![no_std]
#![forbid(unsafe_code)]

//! Safe image projection of node94 `[0x5178be0, 0x5178c37)`.

use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    Current,
    Compare,
    Top,
    Popped,
    Output,
}

fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}

fn load(image: &[u8], range: Range<usize>) -> u64 {
    u64::from_le_bytes(image[range].try_into().unwrap())
}

/// Apply the transition and return its full numeric RAX value.
///
/// `image[j]` represents address `image_base + j` in one nonwrapping image.
/// Effective addresses wrap as u64 before admission. All required ranges are
/// checked before any write, so every error leaves the entire image unchanged.
/// Ordinary stable memory is required; code, control-stack, MMIO and concurrent
/// access are outside this value API. See the accompanying proof for ABI limits.
pub fn transition(image: &mut [u8], image_base: u64, object: u64) -> Result<u64, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let current = span(image, image_base, object.wrapping_add(8), 8).ok_or(AccessError::Current)?;
    let compared =
        span(image, image_base, object.wrapping_add(16), 8).ok_or(AccessError::Compare)?;
    let initial = load(image, current.clone());
    if initial != load(image, compared) {
        let counter =
            span(image, image_base, object.wrapping_add(40), 8).ok_or(AccessError::Output)?;
        let result = initial.wrapping_sub(32);
        let count = load(image, counter.clone()).wrapping_sub(16);
        image[counter].copy_from_slice(&count.to_le_bytes());
        image[current].copy_from_slice(&result.to_le_bytes());
        return Ok(result);
    }
    let top = span(image, image_base, object.wrapping_add(32), 8).ok_or(AccessError::Top)?;
    let next_top = load(image, top.clone()).wrapping_sub(8);
    let popped = span(image, image_base, next_top, 8).ok_or(AccessError::Popped)?;
    let counter = span(image, image_base, object.wrapping_add(40), 8).ok_or(AccessError::Output)?;
    let pair_at =
        span(image, image_base, object.wrapping_add(16), 16).ok_or(AccessError::Output)?;

    image[top].copy_from_slice(&next_top.to_le_bytes());
    let value = load(image, popped);
    let count = load(image, counter.clone()).wrapping_sub(16);
    image[counter].copy_from_slice(&count.to_le_bytes());
    let limit = value.wrapping_add(512);
    let result = limit.wrapping_sub(32);
    let mut pair = [0_u8; 16];
    pair[..8].copy_from_slice(&value.to_le_bytes());
    pair[8..].copy_from_slice(&limit.to_le_bytes());
    image[current].copy_from_slice(&result.to_le_bytes());
    image[pair_at].copy_from_slice(&pair);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pop_reads_after_overlapping_top_store() {
        let mut image = [0_u8; 64];
        image[32..40].copy_from_slice(&40_u64.to_le_bytes());
        assert_eq!(transition(&mut image, 0, 0), Ok(512));
        assert_eq!(load(&image, 16..24), 32);
        assert_eq!(load(&image, 24..32), 544);
        assert_eq!(load(&image, 40..48), u64::MAX - 15);
    }

    #[test]
    fn retreat_does_not_admit_unused_top() {
        let mut image = [0_u8; 64];
        image[8..16].copy_from_slice(&1_u64.to_le_bytes());
        image[32..40].fill(255);
        assert_eq!(transition(&mut image, 0, 0), Ok(u64::MAX - 30));
        assert_eq!(load(&image, 32..40), u64::MAX);
    }

    #[test]
    fn refused_pop_preserves_prior_top() {
        let mut image = [0_u8; 64];
        image[32..40].copy_from_slice(&100_u64.to_le_bytes());
        let before = image;
        assert_eq!(transition(&mut image, 0, 0), Err(AccessError::Popped));
        assert_eq!(image, before);
    }
}
