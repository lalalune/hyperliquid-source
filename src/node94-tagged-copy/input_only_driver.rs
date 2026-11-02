use node94_tagged_copy::{AccessError, tagged_copy};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 154 != 0
        || input
            .chunks_exact(154)
            .any(|row| u16::from_le_bytes(row[24..26].try_into().unwrap()) > 128)
    {
        return Err("partial tagged-copy input or oversized image".into());
    }
    let mut output = Vec::with_capacity(input.len() / 154 * 137);
    for row in input.chunks_exact(154) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[24..26].try_into().unwrap()));
        let mut image: [u8; 128] = row[26..].try_into().unwrap();
        let (tag, value) = match tagged_copy(&mut image[..length], word(0), word(8), word(16)) {
            Ok(value) => (0, value),
            Err(AccessError::ImageRange) => (1, 0),
            Err(AccessError::Input) => (2, 0),
            Err(AccessError::Output) => (3, 0),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
