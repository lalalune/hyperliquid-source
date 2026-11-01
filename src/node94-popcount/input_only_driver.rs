use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 8 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial u64 input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(8) {
        let word = u64::from_le_bytes(row.try_into().unwrap());
        output.write_all(&node94_popcount::count_bits(word).to_le_bytes())?;
        output.write_all(&node94_popcount::count_field(word as u32).to_le_bytes())?;
    }
    output.flush()
}
