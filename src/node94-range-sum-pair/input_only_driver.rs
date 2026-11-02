use node94_range_sum_pair::{Member, apply};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 816 != 0 {
        return Err("partial range-sum-pair input".into());
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(816) {
        let mut f = [0u64; 6];
        for (x, b) in f.iter_mut().zip(row[..48].chunks_exact(8)) {
            *x = u64::from_le_bytes(b.try_into()?);
        }
        if f[0] > 1 || f[5] > 768 {
            return Err("invalid range-sum-pair descriptor".into());
        }
        let member = if f[0] == 0 {
            Member::HelperSum
        } else {
            Member::SlotFieldSum
        };
        let mut image = row[48..].to_vec();
        let result = apply(member, &mut image[..f[5] as usize], f[1], f[2], f[3], f[4]);
        let words = match result {
            Some(r) => [1, r.rax, r.rdx, r.rdi, r.rsi],
            None => [0; 5],
        };
        for word in words {
            output.write_all(&word.to_le_bytes())?;
        }
        output.write_all(&image)?;
    }
    output.flush()?;
    Ok(())
}
