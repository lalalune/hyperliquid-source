//! Native input-only client: stdin is u32 LE triples; stdout is u64 LE results.
//! No expected outputs or fixture paths are compiled into this client.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 12 != 0 {
        return Err("partial input triple".into());
    }
    let mut output = Vec::with_capacity(input.len() / 12 * 8);
    for row in input.chunks_exact(12) {
        let flag = u32::from_le_bytes(row[0..4].try_into()?);
        let first = u32::from_le_bytes(row[4..8].try_into()?);
        let second = u32::from_le_bytes(row[8..12].try_into()?);
        output.extend_from_slice(
            &node94_stack_shift_sum::shift_sum(flag, first, second).to_le_bytes(),
        );
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
