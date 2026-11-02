//! Fixed 49-byte input rows; only this new host client is executed.
use node94_endpoint_gate::{AccessError, gate};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 49 != 0 || input.chunks_exact(49).any(|row| row[40] > 8) {
        return Err("partial endpoint-gate input or oversized image".into());
    }
    let mut output = Vec::with_capacity(input.len() / 49 * 17);
    for row in input.chunks_exact(49) {
        let word = |offset| u64::from_le_bytes(row[offset..offset + 8].try_into().unwrap());
        let result = gate(
            &row[41..41 + usize::from(row[40])],
            word(0),
            word(8),
            word(16),
            word(24),
            word(32),
        );
        let (tag, rax, rdx) = match result {
            Ok(value) => (0, value.rax, value.rdx),
            Err(AccessError::ImageRange) => (1, 0, 0),
            Err(AccessError::Start) => (2, 0, 0),
            Err(AccessError::End) => (3, 0, 0),
        };
        output.push(tag);
        output.extend_from_slice(&rax.to_le_bytes());
        output.extend_from_slice(&rdx.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
