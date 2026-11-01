use node94_byte_dword_gate_pair::{Member, apply};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 160 != 0 {
        return Err("partial byte-dword-gate-pair input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 160 * 24);
    for row in input.chunks_exact(160) {
        let mut words = [0u64; 4];
        for (i, w) in row[..32].chunks_exact(8).enumerate() {
            words[i] = u64::from_le_bytes(w.try_into()?);
        }
        if words[0] > 1 || words[3] > 128 {
            return Err("invalid byte-dword-gate-pair descriptor".into());
        }
        let member = if words[0] == 0 {
            Member::Direct
        } else {
            Member::Tail
        };
        let result = apply(member, &row[32..32 + words[3] as usize], words[1], words[2]);
        let registers = match result {
            Some(r) => [1, r.rax, r.rdx],
            None => [0, 0, 0],
        };
        for value in registers {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
