use node94_threshold_pointer_family::{Flags, Member, select};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 48 != 0 {
        return Err("partial threshold-pointer input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 48 * 24);
    for row in input.chunks_exact(48) {
        let mut words = [0u64; 6];
        for (i, word) in row.chunks_exact(8).enumerate() {
            words[i] = u64::from_le_bytes(word.try_into()?);
        }
        if words[0] > 2 || words[4] > 256 || words[5] > 256 {
            return Err("invalid threshold-pointer descriptor".into());
        }
        let member = match words[0] {
            0 => Member::Plain64,
            1 => Member::Gated36,
            _ => Member::Gated196,
        };
        let flag = |x: u64| if x == 256 { None } else { Some(x as u8) };
        let result = select(
            member,
            words[1],
            words[2],
            words[3],
            Flags {
                first: flag(words[4]),
                second: flag(words[5]),
            },
        );
        let values = match result {
            Some(r) => [1, r.rax, r.rdx],
            None => [0, 0, 0],
        };
        for value in values {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
