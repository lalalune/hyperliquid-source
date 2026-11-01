use node94_conditional_sum_init::initialize;
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 168 != 0 {
        return Err("partial conditional-sum-init input".into());
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(168) {
        let mut f = [0u64; 5];
        for (x, b) in f.iter_mut().zip(row[..40].chunks_exact(8)) {
            *x = u64::from_le_bytes(b.try_into()?);
        }
        if f[4] > 128 {
            return Err("invalid conditional-sum-init descriptor".into());
        }
        let mut image = row[40..].to_vec();
        let result = initialize(&mut image[..f[4] as usize], f[0], f[1], f[2], f[3]);
        let words = match result {
            Some(r) => [1, r.rax, r.rsi, r.rdx],
            None => [0; 4],
        };
        for word in words {
            output.write_all(&word.to_le_bytes())?;
        }
        output.write_all(&image)?;
    }
    output.flush()?;
    Ok(())
}
