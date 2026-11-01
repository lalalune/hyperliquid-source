use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 16 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial i128 input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(16) {
        let value = i128::from_le_bytes(row.try_into().unwrap());
        output.write_all(&node94_i128_f64::to_binary64_bits(value).to_le_bytes())?;
    }
    output.flush()
}
