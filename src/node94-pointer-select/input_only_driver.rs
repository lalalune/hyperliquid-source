//! Input-only native client; expected values and captured instructions are absent.
use node94_pointer_select::{load, Entry};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 2088 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(2088) {
        if u64::from_le_bytes(row[..8].try_into()?) > 2
            || u64::from_le_bytes(row[32..40].try_into()?) > 2048
        {
            return Err("invalid image descriptor".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(2088) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let entry = match word(0) {
            0 => Entry::Direct,
            1 => Entry::Offset24,
            _ => Entry::Offset10672,
        };
        let result = load(
            entry,
            &row[40..40 + word(32) as usize],
            word(8),
            word(16),
            word(24),
        );
        let values = result.map_or([0; 4], |r| [1, r.rax, r.rdi, r.rsi]);
        for value in values {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
