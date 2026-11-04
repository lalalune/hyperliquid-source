#![no_std]

//! Conditional node #115 nonce text values, not the original parser ABI.
//!
//! The accepted prefix is a bracketed sequence of canonical decimal u64s,
//! separated by commas and optionally bytes 09, 0a, 0d and 20. The complete
//! sequence must be strictly increasing. Trailing input remains unconsumed.
//! See the crate README and RE-001 provider proof for native premises and
//! limits, especially the distinction between non-admission and native return.

extern crate alloc;

use alloc::vec::Vec;

/// Chosen source value, with consumption relative to the supplied slice.
#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub values: Vec<u64>,
    pub consumed: usize,
}

/// Source observations and host outcomes, not recovered native enum tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Logical non-admission; does not imply normal native error return.
    NotAdmitted,
    /// Reaching the observed mode-zero/depth-zero failure call after '['.
    DepthZero,
    /// The mode-zero/depth-one ordinary rejection after '['.
    DepthOne,
    /// A complete canonical list fails the credited strict ordering relation.
    OrderingInvariant,
    /// The next initialized length exceeds the native normal domain or host bound.
    HostCapacity,
    /// Actual fallible source reservation failed; not a native OOM observation.
    HostAllocation,
}

const NATIVE_MAX_WORDS: u128 = 1_u128 << 59;

// Parameterizing only the byte bound permits arithmetic checks without enormous
// allocations or pretending that the host has another pointer width.
fn length_fits(required_words: u128, host_max_bytes: u128) -> bool {
    required_words <= NATIVE_MAX_WORDS
        && required_words
            .checked_mul(core::mem::size_of::<u64>() as u128)
            .is_some_and(|bytes| bytes <= host_max_bytes)
}

fn append(values: &mut Vec<u64>, value: u64) -> Result<(), Failure> {
    let required = values.len().checked_add(1).ok_or(Failure::HostCapacity)?;
    if !length_fits(required as u128, isize::MAX as u128) {
        return Err(Failure::HostCapacity);
    }
    // All reservation failures are own-host resource outcomes. Source spare
    // capacity and growth need not reproduce the native allocator's capacity.
    values.try_reserve(1).map_err(|_| Failure::HostAllocation)?;
    values.push(value);
    Ok(())
}

fn skip_whitespace(input: &[u8], cursor: &mut usize) {
    while matches!(input.get(*cursor), Some(b'\t' | b'\n' | b'\r' | b' ')) {
        *cursor += 1;
    }
}

fn integer(input: &[u8], cursor: &mut usize) -> Result<u64, Failure> {
    match input.get(*cursor) {
        Some(b'0') => {
            *cursor += 1;
            // A following digit cannot be a comma or closing delimiter.
            Ok(0)
        }
        Some(b'1'..=b'9') => {
            let mut value = 0_u64;
            while let Some(&digit @ b'0'..=b'9') = input.get(*cursor) {
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u64::from(digit - b'0')))
                    .ok_or(Failure::NotAdmitted)?;
                *cursor += 1;
            }
            Ok(value)
        }
        _ => Err(Failure::NotAdmitted),
    }
}

fn ordered(values: &[u64]) -> bool {
    // SAFETY: exactly N initialized u64s are supplied with capacity=count=N
    // and head=0. A valid slice is within isize::MAX bytes. The empty slice
    // satisfies the zero-capacity case; no native spare capacity is passed.
    unsafe {
        node115_nonce_ring::node115_nonce_ring_is_ordered(
            values.as_ptr(),
            values.len(),
            0,
            values.len(),
        )
    }
}

/// Decode the selected prefix, then apply the existing strict ordering check.
///
/// `input` begins at the selected native entry cursor; mode and depth are raw
/// bytes. Mode zero checks depth only after recognizing an opening bracket.
/// Nonzero mode bypasses depth. Only success exposes consumption and values.
/// Correspondence requires the provider proof's native preservation/ordinary-
/// flow premises and successful own-host capacity admission and reservation.
pub fn decode_nonce_text(input: &[u8], mode: u8, depth: u8) -> Result<Parsed, Failure> {
    let mut cursor = 0;
    skip_whitespace(input, &mut cursor);
    if input.get(cursor) != Some(&b'[') {
        return Err(Failure::NotAdmitted);
    }
    cursor += 1;
    if mode == 0 {
        match depth {
            0 => return Err(Failure::DepthZero),
            1 => return Err(Failure::DepthOne),
            _ => {}
        }
    }

    let mut values = Vec::new();
    skip_whitespace(input, &mut cursor);
    if input.get(cursor) == Some(&b']') {
        cursor += 1;
    } else {
        loop {
            let value = integer(input, &mut cursor)?;
            append(&mut values, value)?;
            skip_whitespace(input, &mut cursor);
            match input.get(cursor) {
                Some(b']') => {
                    cursor += 1;
                    break;
                }
                Some(b',') => {
                    cursor += 1;
                    skip_whitespace(input, &mut cursor);
                }
                _ => return Err(Failure::NotAdmitted),
            }
        }
    }

    // In particular, malformed [2,1,] must not become OrderingInvariant.
    if !ordered(&values) {
        return Err(Failure::OrderingInvariant);
    }
    Ok(Parsed {
        values,
        consumed: cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::length_fits;

    #[test]
    fn pre_source_resource_arithmetic() {
        // Mechanical projection of the independently frozen resource JSON.
        // This tests arithmetic only, not a physical allocator or native OOM.
        let rows = include_str!("../tests/resource-arithmetic.tsv");
        let mut count = 0;
        for row in rows.lines().skip(1) {
            let fields: alloc::vec::Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 3);
            let words: u128 = fields[0].parse().unwrap();
            let max_bytes: u128 = fields[1].parse().unwrap();
            let expected: bool = fields[2].parse().unwrap();
            assert_eq!(length_fits(words, max_bytes), expected, "{row}");
            count += 1;
        }
        assert_eq!(count, 55);
    }
}
