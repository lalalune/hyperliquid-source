#![no_std]
//! Complete logical forward-match helper, ELF VA 0x477e7c0..0x477e941.
//! Native panic objects and unsafe pointer/length ABI are not reproduced.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// Safe adapter restriction; native len-6 wraps when len<6.
    SourceShorterThanSix,
    /// Native (left.len()-6)-cursor subtraction failure-helper edge.
    LeftCursor,
    /// Native right.len()-right_cursor subtraction failure-helper edge.
    RightCursor,
}

/// Extend from two positions, leaving the left input's last six bytes unused.
/// Return the additional equal-byte count and advance only the left cursor.
/// Failure boundaries leave that cursor unchanged. The inputs may alias.
/// This helper does not include the compressor caller's initial four-byte match.
pub fn extend(
    left: &[u8],
    right: &[u8],
    cursor: &mut usize,
    right_cursor: usize,
) -> Result<usize, Boundary> {
    if left.len() < 6 {
        return Err(Boundary::SourceShorterThanSix);
    }
    let left_remaining = (left.len() - 6)
        .checked_sub(*cursor)
        .ok_or(Boundary::LeftCursor)?;
    let right_remaining = right
        .len()
        .checked_sub(right_cursor)
        .ok_or(Boundary::RightCursor)?;
    let limit = left_remaining.min(right_remaining);
    let mut matched = 0;
    while limit - matched >= 8 {
        let a = u64::from_le_bytes(
            left[*cursor + matched..*cursor + matched + 8]
                .try_into()
                .unwrap(),
        );
        let b = u64::from_le_bytes(
            right[right_cursor + matched..right_cursor + matched + 8]
                .try_into()
                .unwrap(),
        );
        let difference = a ^ b;
        if difference != 0 {
            matched += (difference.trailing_zeros() / 8) as usize;
            *cursor += matched;
            return Ok(matched);
        }
        matched += 8;
    }
    while matched < limit && left[*cursor + matched] == right[right_cursor + matched] {
        matched += 1;
    }
    // Both native checked additions are bounded by actual slice extents.
    *cursor += matched;
    Ok(matched)
}
