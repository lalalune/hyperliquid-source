//! Input-only client: member byte, raw RDI, load bias -> full RAX/RDX.
use node94_mixed_lookup_pair::{lookup, Member};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 17 != 0 {
        return Err("partial input record".into());
    }
    if input.chunks_exact(17).any(|row| row[0] > 1) {
        return Err("invalid member descriptor".into());
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(17) {
        let member = if row[0] == 0 {
            Member::At299e280
        } else {
            Member::At29d7fc0
        };
        let result = lookup(
            member,
            u64::from_le_bytes(row[1..9].try_into()?),
            u64::from_le_bytes(row[9..17].try_into()?),
        );
        output.extend_from_slice(&result.rax.to_le_bytes());
        output.extend_from_slice(&result.rdx.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
