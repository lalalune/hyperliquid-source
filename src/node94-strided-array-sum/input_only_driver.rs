//! Input-only host client. Descriptors generate real contiguous u64 tables.
//! No expected sums or expected spans are embedded or read by the client.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 32 != 0 {
        return Err("partial table descriptor".into());
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(32) {
        let index = u32::from_le_bytes(row[0..4].try_into()?);
        let field = u32::from_le_bytes(row[4..8].try_into()?);
        let length = usize::try_from(u64::from_le_bytes(row[8..16].try_into()?))?;
        let seed = u64::from_le_bytes(row[16..24].try_into()?);
        let step = u64::from_le_bytes(row[24..32].try_into()?);
        // Harness allocation bound only; the library has no such count cap.
        if length > 500_000 {
            return Err("fixture table exceeds allocation budget".into());
        }
        let table: Vec<u64> = (0..length)
            .map(|position| seed.wrapping_add(step.wrapping_mul(position as u64)))
            .collect();
        let required = node94_strided_array_sum::required_words(index, field);
        let sum = node94_strided_array_sum::strided_sum(&table, index, field);
        output.push(u8::from(required.is_some()));
        output.extend_from_slice(&(required.unwrap_or(0) as u64).to_le_bytes());
        output.push(u8::from(sum.is_some()));
        output.extend_from_slice(&sum.unwrap_or(0).to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
