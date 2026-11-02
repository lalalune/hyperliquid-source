//! Safe value projection of node94 [0x5560660, 0x55606a8).
#![no_std]
#![forbid(unsafe_code)]

/// New safe admission failures; these are not original machine fault results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessError {
    ImageRange,
    SelectedWord,
}

/// Read the selected little-endian qword from a stable runtime memory image.
///
/// `image_base` names its first byte; `load_bias` relocates the two linked bases.
/// Raw register inputs are accepted, but only their low 32 bits affect selection.
/// The complete selected eight-byte load must fit the nonwrapping image.
/// No logical table length, pointee identity, original ABI or fault behavior is
/// implied. See the accompanying proof for the normal-return correspondence.
pub fn lookup(
    image: &[u8],
    image_base: u64,
    load_bias: u64,
    first: u64,
    mode: u64,
    row: u64,
) -> Result<u64, AccessError> {
    if u128::from(image_base) + image.len() as u128 > (1u128 << 64) {
        return Err(AccessError::ImageRange);
    }
    let first32 = first as u32;
    let gate = first32.wrapping_sub(3);
    let signed_row = i64::from(row as u32 as i32);
    let (linked_base, index) = if gate <= 2 && mode as u32 == 1 {
        (
            0x576db20u64,
            i64::from(gate).wrapping_add(signed_row.wrapping_mul(3)),
        )
    } else {
        (
            0x576d9e0u64,
            i64::from(first32 as i32).wrapping_add(signed_row.wrapping_mul(10)),
        )
    };
    let address = linked_base
        .wrapping_add(load_bias)
        .wrapping_add((index as u64).wrapping_mul(8));
    let offset = address
        .checked_sub(image_base)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(AccessError::SelectedWord)?;
    let end = offset.checked_add(8).ok_or(AccessError::SelectedWord)?;
    let bytes = image.get(offset..end).ok_or(AccessError::SelectedWord)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_paths_and_high_register_bits() {
        let a = 0x1122334455667788u64.to_le_bytes();
        assert_eq!(lookup(&a, 0x576d9e0, 0, 0, 0, 0), Ok(0x1122334455667788));
        assert_eq!(
            lookup(&a, 0x576db20, 0, 0x100000003, 0x100000001, 0x100000000),
            Ok(0x1122334455667788)
        );
    }

    #[test]
    fn signed_row_and_wrapped_runtime_base() {
        let a = 0xfedcba9876543210u64.to_le_bytes();
        assert_eq!(
            lookup(&a, 0x576d9e0 - 80, 0, 0, 0, 0xffffffff),
            Ok(0xfedcba9876543210)
        );
        assert_eq!(
            lookup(&a, 0, 0u64.wrapping_sub(0x576db20), 3, 1, 0),
            Ok(0xfedcba9876543210)
        );
    }

    #[test]
    fn exact_last_qword_and_new_refusals() {
        let a = [0xff; 8];
        assert_eq!(
            lookup(
                &a,
                u64::MAX - 7,
                (u64::MAX - 7).wrapping_sub(0x576db20),
                3,
                1,
                0
            ),
            Ok(u64::MAX)
        );
        assert_eq!(
            lookup(&a[..7], 0x576db20, 0, 3, 1, 0),
            Err(AccessError::SelectedWord)
        );
        assert_eq!(
            lookup(&a, u64::MAX, 0, 3, 1, 0),
            Err(AccessError::ImageRange)
        );
        assert_eq!(
            lookup(&[], u64::MAX, 0, 3, 1, 0),
            Err(AccessError::SelectedWord)
        );
    }
}
