use node94_deep_compare::{AccessError, compare};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 282 != 0
        || input
            .chunks_exact(282)
            .any(|row| u16::from_le_bytes(row[24..26].try_into().unwrap()) > 256)
    {
        return Err("partial deep-compare input or oversized image".into());
    }
    let mut output = Vec::with_capacity(input.len() / 282 * 17);
    for row in input.chunks_exact(282) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[24..26].try_into().unwrap()));
        let (tag, rax, rdx) = match compare(&row[26..26 + length], word(0), word(8), word(16)) {
            Ok(r) => (0, r.rax, r.rdx),
            Err(AccessError::ImageRange) => (1, 0, 0),
            Err(AccessError::FirstHop) => (2, 0, 0),
            Err(AccessError::SecondHop) => (3, 0, 0),
            Err(AccessError::FirstValue) => (4, 0, 0),
            Err(AccessError::SecondValue) => (5, 0, 0),
        };
        output.push(tag);
        output.extend_from_slice(&rax.to_le_bytes());
        output.extend_from_slice(&rdx.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
