use node94_simd_selection_family::{Member, apply};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 704 != 0 {
        return Err("partial simd-selection-family input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 704 * 688);
    for row in input.chunks_exact(704) {
        let mut words = [0u64; 8];
        for (i, w) in row[..64].chunks_exact(8).enumerate() {
            words[i] = u64::from_le_bytes(w.try_into()?);
        }
        if words[0] > 5 || words[7] > 640 {
            return Err("invalid simd-selection-family descriptor".into());
        }
        let member = [
            Member::W32,
            Member::W48,
            Member::W96,
            Member::W192,
            Member::W144,
            Member::W288,
        ][words[0] as usize];
        let mut image = [0u8; 640];
        image.copy_from_slice(&row[64..]);
        let result = apply(
            member,
            &mut image[..words[7] as usize],
            words[1],
            words[2],
            words[3],
            words[4],
            words[5],
            words[6],
        );
        let registers = match result {
            Some(r) => [1, r.rax, r.rcx, r.rdi, r.rsi, r.rdx],
            None => [0; 6],
        };
        for value in registers {
            output.extend_from_slice(&value.to_le_bytes());
        }
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
