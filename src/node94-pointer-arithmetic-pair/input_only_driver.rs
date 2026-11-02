//! Fixed input-only records; no expected values or captured execution.
use node94_pointer_arithmetic_pair::{select, AccessError};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 1042 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(1042) {
        if u16::from_le_bytes(row[16..18].try_into()?) > 1024 {
            return Err("image length exceeds backing storage".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(1042) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[16..18].try_into()?));
        let (tag, rax, rdx) = match select(&row[18..18 + length], word(0), word(8)) {
            Ok(r) => (0, r.rax, r.rdx),
            Err(AccessError::ImageRange) => (1, 0, 0),
            Err(AccessError::PrimaryFlag) => (2, 0, 0),
            Err(AccessError::StoredPair) => (3, 0, 0),
            Err(AccessError::SecondaryFlag) => (4, 0, 0),
            Err(AccessError::ComputedWords) => (5, 0, 0),
        };
        output.push(tag);
        output.extend_from_slice(&rax.to_le_bytes());
        output.extend_from_slice(&rdx.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
