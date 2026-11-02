use node94_gated_field_pair::{Member, Registers, apply};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 856 != 0 {
        return Err("partial gated-field-pair input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 856 * 824);
    for row in input.chunks_exact(856) {
        let mut words = [0u64; 7];
        for (i, w) in row[..56].chunks_exact(8).enumerate() {
            words[i] = u64::from_le_bytes(w.try_into()?);
        }
        if words[0] > 1 || words[6] > 800 {
            return Err("invalid gated-field-pair descriptor".into());
        }
        let member = if words[0] == 0 {
            Member::CopyOut
        } else {
            Member::CopyIn
        };
        let mut image = [0u8; 800];
        image.copy_from_slice(&row[56..]);
        let result = apply(
            member,
            &mut image[..words[6] as usize],
            words[1],
            words[2],
            words[3],
            Registers {
                rax: words[4],
                rdx: words[5],
            },
        );
        let registers = match result {
            Some(r) => [1, r.rax, r.rdx],
            None => [0, 0, 0],
        };
        for value in registers {
            output.extend_from_slice(&value.to_le_bytes());
        }
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
