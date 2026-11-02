//! Input-only image client; expected outputs and target instructions are absent.
use node94_self_guarded_chain::load;
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 152 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(152) {
        if u64::from_le_bytes(row[16..24].try_into()?) > 128 {
            return Err("invalid image descriptor".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(152) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let result = load(&row[24..24 + word(16) as usize], word(0), word(8));
        let words = result.map_or([0, 0, 0], |r| [1, r.rax, r.rdx]);
        for value in words {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
