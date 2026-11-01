//! Descriptors create ordinary arenas; only new Rust computes their outputs.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 40 != 0 {
        return Err("partial arena descriptor".into());
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(40) {
        let source = usize::try_from(u64::from_le_bytes(row[0..8].try_into()?))?;
        let destination = usize::try_from(u64::from_le_bytes(row[8..16].try_into()?))?;
        let available = usize::try_from(u64::from_le_bytes(row[16..24].try_into()?))?;
        let seed = u64::from_le_bytes(row[24..32].try_into()?);
        let pattern = u64::from_le_bytes(row[32..40].try_into()?);
        if available > 256 {
            return Err("fixture arena exceeds backing storage".into());
        }
        if pattern > 2 {
            return Err("unknown fixture pattern".into());
        }
        let mut arena = core::array::from_fn::<_, 256, _>(|position| match pattern {
            0 => (position as u8).wrapping_add(seed as u8),
            1 => seed as u8,
            _ => {
                if position as u64 == seed {
                    128
                } else {
                    0
                }
            }
        });
        let result =
            node94_reversed_record_copy::copy_record(&mut arena[..available], source, destination);
        output.push(u8::from(result.is_some()));
        output.extend_from_slice(&(result.unwrap_or(0) as u64).to_le_bytes());
        output.extend_from_slice(&arena);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
