use node94_three_digit_parser::parse;
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 24 != 0 {
        return Err("partial three-digit input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 24 * 16);
    for row in input.chunks_exact(24) {
        let length = u64::from_le_bytes(row[0..8].try_into()?);
        let available = u64::from_le_bytes(row[8..16].try_into()?);
        let packed = u64::from_le_bytes(row[16..24].try_into()?);
        if available > 4 || packed > u64::from(u32::MAX) {
            return Err("invalid three-digit descriptor".into());
        }
        let bytes = (packed as u32).to_le_bytes();
        let (status, rax) = match parse(length, &bytes[..available as usize]) {
            Ok(value) => (0_u64, value),
            Err(_) => (1_u64, 0),
        };
        output.extend_from_slice(&status.to_le_bytes());
        output.extend_from_slice(&rax.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
