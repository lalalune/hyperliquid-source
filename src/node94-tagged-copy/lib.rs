#![no_std]
#![forbid(unsafe_code)]

//! Safe image projection of node94 `[0x22155a0,0x22155c0)`.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    Input,
    Output,
}

fn offset(image: &[u8], base: u64, address: u64, width: usize) -> Option<usize> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    (start.checked_add(width)? <= image.len()).then_some(start)
}

/// Snapshot 32 input bytes, write them after the fixed tag, and return raw RAX.
///
/// Image byte j represents `image_base + j` in a nonwrapping address range.
/// Input/output may overlap at any byte displacement. Both complete ranges
/// are checked before writes, so new safe errors leave all bytes unchanged.
/// Ordinary stable valid target accesses are assumed for correspondence;
/// original faults, pointer ABI and intermediate observations are not modeled.
pub fn tagged_copy(
    image: &mut [u8],
    image_base: u64,
    source: u64,
    destination: u64,
) -> Result<u64, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let input = offset(image, image_base, source, 32).ok_or(AccessError::Input)?;
    let output = offset(image, image_base, destination, 40).ok_or(AccessError::Output)?;
    let payload: [u8; 32] = image[input..input + 32].try_into().unwrap();
    image[output + 8..output + 40].copy_from_slice(&payload);
    image[output..output + 8].copy_from_slice(&0x8000_0000_0000_0014_u64.to_le_bytes());
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_address_retains_original_payload() {
        let mut image = [0_u8; 40];
        for (i, byte) in image[..32].iter_mut().enumerate() {
            *byte = i as u8;
        }
        let original: [u8; 32] = image[..32].try_into().unwrap();
        assert_eq!(tagged_copy(&mut image, 0, 0, 0), Ok(0));
        assert_eq!(&image[8..40], &original);
        assert_eq!(&image[..8], &[20, 0, 0, 0, 0, 0, 0, 128]);
    }

    #[test]
    fn final_address_may_be_u64_max() {
        let mut image = [7_u8; 40];
        let base = u64::MAX - 39;
        assert_eq!(tagged_copy(&mut image, base, base, base), Ok(base));
        assert_eq!(&image[8..], &[7; 32]);
    }

    #[test]
    fn missing_output_is_atomic() {
        let mut image = [7_u8; 39];
        assert_eq!(tagged_copy(&mut image, 0, 0, 0), Err(AccessError::Output));
        assert_eq!(image, [7; 39]);
    }
}
