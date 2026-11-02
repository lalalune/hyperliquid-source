use node94_scaled_advance::advance;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 24 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial scaled-advance input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(24) {
        let mut cursor = u64::from_le_bytes(row[..8].try_into().unwrap());
        let end = u64::from_le_bytes(row[8..16].try_into().unwrap());
        let requested = u64::from_le_bytes(row[16..24].try_into().unwrap());
        let remainder = advance(&mut cursor, end, requested);
        output.write_all(&cursor.to_le_bytes())?;
        output.write_all(&remainder.to_le_bytes())?;
    }
    output.flush()
}
