use node94_global_clamp::initialize;
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 32 != 0 {
        return Err("partial global-clamp input".into());
    }
    let mut output = Vec::with_capacity(input.len());
    for row in input.chunks_exact(32) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let mut state = [word(8), word(16), word(24)];
        let rax = initialize(word(0) as i64, &mut state);
        output.extend_from_slice(&rax.to_le_bytes());
        for value in state {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
