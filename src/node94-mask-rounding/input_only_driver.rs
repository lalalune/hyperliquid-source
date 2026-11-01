use node94_mask_rounding::bound_value;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut inputs = Vec::new();
    io::stdin().read_to_end(&mut inputs)?;
    if inputs.len() % 8 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial u64 input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in inputs.chunks_exact(8) {
        let value = u64::from_le_bytes(row.try_into().unwrap());
        output.write_all(&bound_value(value).to_le_bytes())?;
    }
    output.flush()
}
