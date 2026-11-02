//! Alias-aware value/store projection of node94 ELF VA 0x54ccfb0..0x54cd009.
#![no_std]
#![forbid(unsafe_code)]

use core::ops::Range;

/// New safe admission failures; each leaves the complete image unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    StateBounds,
    OutputBounds,
    TableBounds,
}

fn span(image_base: u64, address: u64, width: usize, length: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(image_base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= length).then_some(start..end)
}

/// Preserve the optional output store before the selected table load.
///
/// `table_base` is the runtime address produced by the original RIP-relative
/// LEA (linked ELF VA 0x5799cc0, plus the actual load bias). Image byte i denotes
/// image_base+i. Object/output zero retain their native null meanings. Low32
/// index bits select the state byte and table word. Successful calls preserve
/// every overlap within this ordinary byte image. Invalid accesses are refused
/// before mutation; native faults and partial writes are not reproduced.
pub fn apply(
    image: &mut [u8],
    image_base: u64,
    object: u64,
    base: u64,
    raw_index: u64,
    out: u64,
    table_base: u64,
) -> Result<u64, AccessError> {
    if let Some(last) = image.len().checked_sub(1) {
        let last = u64::try_from(last).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let index = u64::from(raw_index as u32);
    let selector = if object == 0 {
        0
    } else {
        let address = object.checked_add(0x90).ok_or(AccessError::StateBounds)?;
        let range = span(image_base, address, 8, image.len()).ok_or(AccessError::StateBounds)?;
        let present = u64::from_le_bytes(image[range].try_into().unwrap());
        if present == 0 {
            0
        } else {
            let address = object
                .checked_add(0xa1)
                .and_then(|address| address.checked_add(index))
                .ok_or(AccessError::StateBounds)?;
            let range =
                span(image_base, address, 1, image.len()).ok_or(AccessError::StateBounds)?;
            image[range.start]
        }
    };
    let output = if out != 0 {
        Some(span(image_base, out, 4, image.len()).ok_or(AccessError::OutputBounds)?)
    } else {
        None
    };
    let address = table_base
        .checked_add(index * 4)
        .ok_or(AccessError::TableBounds)?;
    let table = span(image_base, address, 4, image.len()).ok_or(AccessError::TableBounds)?;
    if let Some(range) = output {
        image[range].copy_from_slice(&u32::from(selector).to_le_bytes());
    }
    let entry = u32::from_le_bytes(image[table].try_into().unwrap());
    Ok(base
        .wrapping_add(u64::from(entry))
        .wrapping_add(u64::from(selector) * 224))
}

#[cfg(test)]
mod tests {
    use super::{AccessError, apply};

    #[test]
    fn output_alias_changes_loaded_table_word() {
        let mut image = [0_u8; 320];
        image[160] = 1;
        image[177] = 7;
        image[256..260].copy_from_slice(&0xfedcba98_u32.to_le_bytes());
        assert_eq!(apply(&mut image, 4096, 4112, 10, 0, 4352, 4352), Ok(1585));
        assert_eq!(&image[256..260], &[7, 0, 0, 0]);
    }

    #[test]
    fn null_object_still_stores_and_loads_afterward() {
        let mut image = [255_u8; 4];
        assert_eq!(
            apply(&mut image, 100, 0, u64::MAX, 0, 100, 100),
            Ok(u64::MAX)
        );
        assert_eq!(image, [0; 4]);
    }

    #[test]
    fn missing_table_is_atomic() {
        let mut image = [37_u8; 8];
        assert_eq!(
            apply(&mut image, 100, 0, 0, 0, 100, 107),
            Err(AccessError::TableBounds)
        );
        assert_eq!(image, [37; 8]);
    }
}
