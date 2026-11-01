use node94_cursor_family::{Member, apply};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 168 != 0 {
        return Err("partial cursor-family input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 168 * 152);
    for row in input.chunks_exact(168) {
        let mut words = [0u64; 5];
        for (i, w) in row[..40].chunks_exact(8).enumerate() {
            words[i] = u64::from_le_bytes(w.try_into()?);
        }
        if words[0] > 3 || words[4] > 128 {
            return Err("invalid cursor-family descriptor".into());
        }
        let member = match words[0] {
            0 => Member::Span,
            1 => Member::Read,
            2 => Member::Advance,
            _ => Member::Retreat,
        };
        let mut image = [0u8; 128];
        image.copy_from_slice(&row[40..]);
        let result = apply(
            member,
            &mut image[..words[4] as usize],
            words[1],
            words[2],
            words[3],
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
