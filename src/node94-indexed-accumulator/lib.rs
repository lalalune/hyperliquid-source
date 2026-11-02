//! Safe ordinary-memory projection of node94 [0x514ac60, 0x514ac8c).
#![no_std]
#![forbid(unsafe_code)]

use core::ops::Range;

/// New admission errors, all leaving the entire image unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AccessError {
    ImageRange = 1,
    SelectorPointer = 2,
    Addend = 3,
    IndexField = 4,
    BaseSlot = 5,
    Counter = 6,
    Sum = 7,
}

fn span(image: &[u8], image_base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(image_base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}

fn load_u64(image: &[u8], range: Range<usize>) -> u64 {
    u64::from_le_bytes(image[range].try_into().unwrap())
}

/// Increment the selected counter, accumulate the snapshotted addend, and
/// return the full numeric entry address left in original RAX.
///
/// Image byte j represents image_base+j. The three address arguments correspond
/// to original R8, RCX and RDI, respectively. A loaded zero selector pointer
/// chooses index 13; otherwise its +32 field supplies a signed 32-bit index.
/// Effective address calculations wrap as u64, but each actual memory access
/// must fit the nonwrapping image. Both output spans are admitted before stores.
/// Ordinary stable bytes may alias; faults and control-state aliasing are excluded.
pub fn accumulate(
    image: &mut [u8],
    image_base: u64,
    selector_slot: u64,
    addend_address: u64,
    base_slot: u64,
) -> Result<u64, AccessError> {
    if let Some(last) = image.len().checked_sub(1) {
        let last = u64::try_from(last).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let pointer = load_u64(
        image,
        span(image, image_base, selector_slot, 8).ok_or(AccessError::SelectorPointer)?,
    );
    let addend = load_u64(
        image,
        span(image, image_base, addend_address, 8).ok_or(AccessError::Addend)?,
    );
    let index = if pointer == 0 {
        13_u64
    } else {
        let range =
            span(image, image_base, pointer.wrapping_add(32), 4).ok_or(AccessError::IndexField)?;
        i32::from_le_bytes(image[range].try_into().unwrap()) as i64 as u64
    };
    let base = load_u64(
        image,
        span(image, image_base, base_slot, 8).ok_or(AccessError::BaseSlot)?,
    );
    let entry = base.wrapping_add(index.wrapping_mul(8));
    let counter =
        span(image, image_base, entry.wrapping_add(176), 8).ok_or(AccessError::Counter)?;
    let sum = span(image, image_base, entry.wrapping_add(64), 8).ok_or(AccessError::Sum)?;
    let incremented = load_u64(image, counter.clone()).wrapping_add(1);
    image[counter].copy_from_slice(&incremented.to_le_bytes());
    let accumulated = load_u64(image, sum.clone()).wrapping_add(addend);
    image[sum].copy_from_slice(&accumulated.to_le_bytes());
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::{accumulate, AccessError};

    fn put(image: &mut [u8], at: usize, value: u64) {
        image[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn return_is_entry_address_and_addend_is_snapshotted() {
        let mut image = [0_u8; 512];
        put(&mut image, 40, 4096 + 224 - 13 * 8);
        put(&mut image, 400, 7);
        put(&mut image, 288, 10);
        assert_eq!(accumulate(&mut image, 4096, 4104, 4496, 4136), Ok(4320));
        assert_eq!(&image[400..408], &8_u64.to_le_bytes());
        assert_eq!(&image[288..296], &17_u64.to_le_bytes());
    }

    #[test]
    fn signed_index_and_wrapped_effective_addresses() {
        let mut image = [0_u8; 256];
        put(&mut image, 8, u64::MAX - 31);
        image[..4].copy_from_slice(&(-1_i32).to_le_bytes());
        put(&mut image, 40, 7);
        put(&mut image, 24, u64::MAX);
        put(&mut image, 175, u64::MAX);
        put(&mut image, 63, 3);
        assert_eq!(accumulate(&mut image, 0, 8, 24, 40), Ok(u64::MAX));
        assert_eq!(&image[175..183], &[0; 8]);
        assert_eq!(&image[63..71], &2_u64.to_le_bytes());
    }

    #[test]
    fn missing_sum_refuses_before_counter_write() {
        let mut image = [0_u8; 192];
        put(&mut image, 40, u64::MAX - 64 - 13 * 8);
        put(&mut image, 111, 9);
        let original = image;
        assert_eq!(accumulate(&mut image, 0, 8, 24, 40), Err(AccessError::Sum));
        assert_eq!(image, original);
    }
}
