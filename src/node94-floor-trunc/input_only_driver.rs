use node94_floor_trunc::{floor_bits, trunc_bits};
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 9 != 0 || input.chunks_exact(9).any(|row| row[8] > 1) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid input framing or DAZ byte",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(9) {
        let bits = u64::from_le_bytes(row[..8].try_into().unwrap());
        output.write_all(&trunc_bits(bits).to_le_bytes())?;
        output.write_all(&floor_bits(bits, row[8] != 0).to_le_bytes())?;
    }
    output.flush()
}
