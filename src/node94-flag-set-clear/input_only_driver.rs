use node94_flag_set_clear::apply;
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 544 != 0 {
        return Err("partial flag-set-clear input".into());
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(544) {
        let mut f = [0u64; 4];
        for (x, b) in f.iter_mut().zip(row[..32].chunks_exact(8)) {
            *x = u64::from_le_bytes(b.try_into()?);
        }
        if f[3] > 512 {
            return Err("invalid flag-set-clear descriptor".into());
        }
        let mut image = row[32..].to_vec();
        let result = apply(&mut image[..f[3] as usize], f[0], f[1], f[2]);
        let words = match result {
            Some(r) => [1, r.rax, r.rdx],
            None => [0; 3],
        };
        for word in words {
            output.write_all(&word.to_le_bytes())?;
        }
        output.write_all(&image)?;
    }
    output.flush()?;
    Ok(())
}
