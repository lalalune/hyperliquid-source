//! Safe normal-return predicate for node94 [0x51a5d60, 0x51a5da8).
#![no_std]
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccessError {
    ImageRange = 1,
    RootSlot = 2,
    Flag = 3,
    Head = 4,
    Field = 5,
    Link = 6,
    Cycle = 7,
}

fn bytes<const N: usize>(image: &[u8], image_base: u64, address: u64) -> Option<[u8; N]> {
    let start = usize::try_from(address.checked_sub(image_base)?).ok()?;
    let end = start.checked_add(N)?;
    image.get(start..end)?.try_into().ok()
}

/// Return the original normal-return RAX predicate as a bool.
///
/// Image byte j denotes image_base+j. Effective addresses wrap as u64; actual
/// accesses must fit this nonwrapping, immutable ordinary image. The entry RDI
/// argument is root_slot. A nonzero flag skips the head; a nonzero node field
/// skips its link. Bounds errors and Cycle are new safe outcomes. Cycle means
/// the native read-only walk would repeat forever on this stable image.
pub fn all_zero(image: &[u8], image_base: u64, root_slot: u64) -> Result<bool, AccessError> {
    if let Some(last) = image.len().checked_sub(1) {
        let last = u64::try_from(last).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let object =
        u64::from_le_bytes(bytes(image, image_base, root_slot).ok_or(AccessError::RootSlot)?);
    let flag = bytes::<1>(image, image_base, object.wrapping_add(112)).ok_or(AccessError::Flag)?[0];
    if flag != 0 {
        return Ok(false);
    }
    let mut node = u64::from_le_bytes(
        bytes(image, image_base, object.wrapping_add(72)).ok_or(AccessError::Head)?,
    );
    // A length-L image has at most max(L-7,0) distinct qword-start addresses.
    // Check this only after a zero field and a valid link, so terminal paths
    // never need a readable link or consume an invented traversal allowance.
    let mut remaining = image.len().saturating_sub(7);
    while node != 0 {
        let field = u64::from_le_bytes(
            bytes(image, image_base, node.wrapping_add(16)).ok_or(AccessError::Field)?,
        );
        if field != 0 {
            return Ok(false);
        }
        let following =
            u64::from_le_bytes(bytes(image, image_base, node).ok_or(AccessError::Link)?);
        if remaining == 0 {
            return Err(AccessError::Cycle);
        }
        remaining -= 1;
        node = following;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{all_zero, AccessError};

    fn put(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn flag_first_does_not_require_head_mapping() {
        let mut image = [0_u8; 64];
        put(&mut image, 16, 4096 - 112);
        image[0] = 128;
        assert_eq!(all_zero(&image, 4096, 4112), Ok(false));
        image[0] = 0;
        assert_eq!(all_zero(&image, 4096, 4112), Err(AccessError::Head));
    }

    #[test]
    fn null_head_and_full_width_nonzero_field() {
        let mut image = [0_u8; 256];
        put(&mut image, 8, 32);
        assert_eq!(all_zero(&image, 0, 8), Ok(true));
        put(&mut image, 104, 160);
        put(&mut image, 160, u64::MAX);
        put(&mut image, 176, 1_u64 << 63);
        assert_eq!(all_zero(&image, 0, 8), Ok(false));
    }

    #[test]
    fn zero_cycle_is_distinct_from_nonzero_cycle_node() {
        let mut image = [0_u8; 256];
        put(&mut image, 8, 32);
        put(&mut image, 104, 160);
        put(&mut image, 160, 160);
        assert_eq!(all_zero(&image, 0, 8), Err(AccessError::Cycle));
        put(&mut image, 176, 1);
        assert_eq!(all_zero(&image, 0, 8), Ok(false));
    }
}
