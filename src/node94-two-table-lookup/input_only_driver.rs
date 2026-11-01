//! Native synthetic input-only client. No expected stream is read here.
use node94_two_table_lookup::{lookup, AccessError};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 554 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(554) {
        if u16::from_le_bytes(row[40..42].try_into()?) > 512 {
            return Err("image length exceeds backing storage".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(554) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[40..42].try_into()?));
        let (tag, value) = match lookup(
            &row[42..42 + length],
            word(0),
            word(8),
            word(16),
            word(24),
            word(32),
        ) {
            Ok(value) => (0, value),
            Err(AccessError::ImageRange) => (1, 0),
            Err(AccessError::SelectedWord) => (2, 0),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
