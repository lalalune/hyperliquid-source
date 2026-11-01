use node94_modulo_index::{Refusal, hash_for_index, lookup};
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 784 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial modulo-index input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(784) {
        let index = u64::from_le_bytes(row[..8].try_into().unwrap());
        let divisor = u16::from_le_bytes(row[8..10].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[10..12].try_into().unwrap()));
        let table_length = u32::from_le_bytes(row[12..16].try_into().unwrap()) as usize;
        if length > 256 || table_length > 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid modulo-index descriptor",
            ));
        }
        let bytes = &row[16..16 + length];
        let table = &row[272..272 + table_length];
        let hash = hash_for_index(bytes);
        let (tag, byte) = match lookup(bytes, divisor, table, index) {
            Ok(byte) => (0, byte),
            Err(Refusal::ZeroDivisor) => (1, 0),
            Err(Refusal::TableBounds) => (2, 0),
        };
        output.write_all(&hash.to_le_bytes())?;
        output.write_all(&[tag, byte])?;
    }
    output.flush()
}
