//! Fixed input-only records, no expected values and no target execution.
use node94_min_gap_prefix::{compare, AccessError};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 282 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(282) {
        if u16::from_le_bytes(row[24..26].try_into()?) > 256 {
            return Err("image length exceeds backing storage".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(282) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[24..26].try_into()?));
        let (tag, value) = match compare(&row[26..26 + length], word(0), word(8), word(16)) {
            Ok(value) => (0, value),
            Err(AccessError::ImageRange) => (1, 0),
            Err(AccessError::Lengths) => (2, 0),
            Err(AccessError::Pointers) => (3, 0),
            Err(AccessError::Bytes) => (4, 0),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
