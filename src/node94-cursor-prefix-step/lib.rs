#![no_std]
#![forbid(unsafe_code)]

//! Safe byte-image reconstruction of node #94 VA 0x47d6b90.
//! Prefix aliases observe the counter store. See README.md for admission and
//! the distinction between this image API and native pointers/fault behavior.
use core::ops::Range;

const COUNTER: usize = 0x1e0;
const CURSOR: usize = 0x1d0;
const FLAG: usize = 0x1f0;
const MARKER: usize = 0x1f3;

/// Raw register observation, without a recovered source return signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedRax {
    Unchanged,
    Value(u64),
}

/// Admission failure; the complete image remains unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    StateBounds,
    PrefixBounds,
}

fn field(
    state: usize,
    offset: usize,
    width: usize,
    len: usize,
) -> Result<Range<usize>, AccessError> {
    let start = state.checked_add(offset).ok_or(AccessError::StateBounds)?;
    let end = start.checked_add(width).ok_or(AccessError::StateBounds)?;
    if end > len {
        return Err(AccessError::StateBounds);
    }
    Ok(start..end)
}

/// Apply one transition, including aliases between prefix bytes and state.
///
/// Image byte i denotes address base+i. All required reads/writes are checked
/// before mutation. Marker paths need no mapped prefix. Advance reads the prefix
/// after storing counter-2 and permits any resulting cursor, including wrapping
/// or outside-image values. Rejection policy is additional to the native body.
pub fn step(image: &mut [u8], base: u64, state: usize) -> Result<ObservedRax, AccessError> {
    if let Some(last) = image.len().checked_sub(1) {
        let last = u64::try_from(last).map_err(|_| AccessError::ImageRange)?;
        base.checked_add(last).ok_or(AccessError::ImageRange)?;
    }
    let flag = field(state, FLAG, 1, image.len())?.start;
    if image[flag] == 0 {
        let marker = field(state, MARKER, 1, image.len())?.start;
        image[marker] = 0x67;
        return Ok(ObservedRax::Unchanged);
    }
    let counter_range = field(state, COUNTER, 8, image.len())?;
    let counter = u64::from_le_bytes(image[counter_range.clone()].try_into().unwrap());
    if counter <= 1 {
        let marker = field(state, MARKER, 1, image.len())?.start;
        image[marker] = 0x50;
        return Ok(ObservedRax::Value(counter));
    }
    let cursor_range = field(state, CURSOR, 8, image.len())?;
    let cursor = u64::from_le_bytes(image[cursor_range.clone()].try_into().unwrap());
    let prefix_start = cursor
        .checked_sub(base)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(AccessError::PrefixBounds)?;
    let prefix_end = prefix_start
        .checked_add(2)
        .ok_or(AccessError::PrefixBounds)?;
    if prefix_end > image.len() {
        return Err(AccessError::PrefixBounds);
    }
    image[counter_range].copy_from_slice(&counter.wrapping_sub(2).to_le_bytes());
    let prefix = [image[prefix_start], image[prefix_start + 1]];
    let delta = i64::from(i16::from_be_bytes(prefix)) + 2;
    let next_cursor = cursor.wrapping_add(delta as u64);
    image[cursor_range].copy_from_slice(&next_cursor.to_le_bytes());
    Ok(ObservedRax::Value(next_cursor))
}
