use node94_dual_load::lookup;
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 9 != 0 {
        return Err("partial dual-load input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 9 * 16);
    for row in input.chunks_exact(9) {
        let result = lookup(row[0], u64::from_le_bytes(row[1..].try_into().unwrap()));
        output.extend_from_slice(&result.rax.to_le_bytes());
        output.extend_from_slice(&result.rdx.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
