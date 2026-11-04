//! Logical-byte reconstruction of node #115's size-prefixed LZ4 block adapter.
//! See the evidence packet for native ABI, speculative-copy and helper limits.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Header,
    Limit,
    Input,
    Literal,
    Output,
    ZeroOffset,
    History,
    /// The target reaches a checked u32-add panic; this safe API reports it.
    ExtensionOverflow,
    /// Local allocation policy, outside target-normal-return comparisons.
    Allocation,
}

fn extended(input: &[u8], cursor: &mut usize, base: usize) -> Result<usize, DecodeError> {
    let mut extra = 0u32;
    loop {
        let byte = *input.get(*cursor).ok_or(DecodeError::Input)?;
        *cursor += 1;
        extra = extra
            .checked_add(u32::from(byte))
            .ok_or(DecodeError::ExtensionOverflow)?;
        if byte != 255 {
            return Ok(base + extra as usize);
        }
    }
}

/// Decode a four-byte little-endian capacity followed by one LZ4 block.
///
/// The announced capacity is checked against `maximum` before allocation.
/// Successful output may be shorter than the announced capacity. A final
/// literal sequence ignores its match nibble; an ending match needs another
/// token, including a zero-literal terminal token. No I/O is performed.
///
/// Requires a 64-bit host for the target's usize arithmetic. Allocation and
/// boxed errors deliberately use this library's API, not the captured ABI.
pub fn decode(input: &[u8], maximum: u64) -> Result<Vec<u8>, DecodeError> {
    assert!(usize::BITS == 64, "node115 contract requires a 64-bit host");
    let prefix: [u8; 4] = input
        .get(..4)
        .ok_or(DecodeError::Header)?
        .try_into()
        .expect("four-byte slice");
    let capacity = u32::from_le_bytes(prefix) as usize;
    if capacity as u64 > maximum {
        return Err(DecodeError::Limit);
    }
    let block = &input[4..];
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| DecodeError::Allocation)?;
    let mut cursor = 0usize;
    loop {
        let token = *block.get(cursor).ok_or(DecodeError::Input)?;
        cursor += 1;
        let mut literals = usize::from(token >> 4);
        if literals == 15 {
            literals = extended(block, &mut cursor, 15)?;
        }
        if literals > block.len() - cursor {
            return Err(DecodeError::Literal);
        }
        if literals > capacity - output.len() {
            return Err(DecodeError::Output);
        }
        output.extend_from_slice(&block[cursor..cursor + literals]);
        cursor += literals;
        if cursor == block.len() {
            return Ok(output);
        }
        let pair = block.get(cursor..cursor + 2).ok_or(DecodeError::Input)?;
        let distance = usize::from(u16::from_le_bytes([pair[0], pair[1]]));
        cursor += 2;
        if distance == 0 {
            return Err(DecodeError::ZeroOffset);
        }
        let mut length = usize::from(token & 15) + 4;
        if length == 19 {
            length = extended(block, &mut cursor, 19)?;
        }
        if length > capacity - output.len() {
            return Err(DecodeError::Output);
        }
        if distance > output.len() {
            return Err(DecodeError::History);
        }
        // Recompute the source after each append: an earlier match byte can
        // become the source of a later byte in the same overlapping match.
        for _ in 0..length {
            let value = output[output.len() - distance];
            output.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_match_and_terminal_token() {
        assert_eq!(
            decode(&[8, 0, 0, 0, 0x13, b'A', 1, 0, 0], 8),
            Ok(vec![b'A'; 8])
        );
        assert_eq!(
            decode(&[8, 0, 0, 0, 0x13, b'A', 1, 0], 8),
            Err(DecodeError::Input)
        );
    }

    #[test]
    fn announced_capacity_is_not_exact_length() {
        assert_eq!(decode(&[9, 0, 0, 0, 0x1f, b'Z'], 9), Ok(vec![b'Z']));
        assert_eq!(decode(&[0, 0, 0, 0, 0x0f], 0), Ok(vec![]));
        assert_eq!(decode(&[0, 0, 0, 0], 0), Err(DecodeError::Input));
    }

    #[test]
    fn target_error_precedence() {
        assert_eq!(
            decode(&[0, 0, 0, 0, 0x20, b'A'], 0),
            Err(DecodeError::Literal)
        );
        assert_eq!(decode(&[0, 0, 0, 0, 0, 1, 0], 0), Err(DecodeError::Output));
        assert_eq!(
            decode(&[8, 0, 0, 0, 0x0f, 0, 0], 8),
            Err(DecodeError::ZeroOffset)
        );
    }
}
