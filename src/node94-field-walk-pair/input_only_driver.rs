//! Input-only synthetic-image client; no expected outputs or captured instructions.
use node94_field_walk_pair::{apply, Member};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 176 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(176) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        if word(0) > 1 || word(40) > 128 {
            return Err("invalid member/image descriptor".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(176) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let member = if word(0) == 0 {
            Member::ShiftedDifference
        } else {
            Member::SignedField
        };
        let mut image: [u8; 128] = row[48..].try_into()?;
        let result = apply(
            member,
            &mut image[..word(40) as usize],
            word(8),
            word(16),
            word(24),
            word(32),
        );
        let registers = result.map_or([0, 0, 0], |r| [1, r.rax, r.rdx]);
        for value in registers {
            output.extend_from_slice(&value.to_le_bytes());
        }
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
