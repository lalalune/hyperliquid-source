//! Input-only client: little-endian input words in, two result words out.
//! No expected results or evidence files are available to this client.
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 8 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial input word",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for word in input.chunks_exact(8) {
        let bits = u64::from_le_bytes(word.try_into().unwrap());
        output.write_all(&node94_ceil::ceil_bits(bits).to_le_bytes())?;
        output.write_all(
            &node94_ceil::ceil(f64::from_bits(bits))
                .to_bits()
                .to_le_bytes(),
        )?;
    }
    output.flush()
}
