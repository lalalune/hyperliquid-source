//! Input-only descriptors and real mutable bytes; no supplied expectations.
use node94_tag_store::{store, AccessError};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 106 != 0 {
        return Err("partial input record".into());
    }
    if input
        .chunks_exact(106)
        .any(|r| u16::from_le_bytes(r[40..42].try_into().unwrap()) > 64)
    {
        return Err("image length exceeds backing storage".into());
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(106) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[40..42].try_into()?));
        let mut image: [u8; 64] = row[42..].try_into()?;
        let (tag, rax) = match store(
            &mut image[..length],
            word(0),
            word(8),
            word(16),
            word(24),
            word(32),
        ) {
            Ok(rax) => (0, rax),
            Err(AccessError::ImageRange) => (1, 0),
            Err(AccessError::Source) => (2, 0),
            Err(AccessError::Destination) => (3, 0),
        };
        output.push(tag);
        output.extend_from_slice(&rax.to_le_bytes());
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
