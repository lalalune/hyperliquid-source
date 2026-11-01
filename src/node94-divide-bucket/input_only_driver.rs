use node94_divide_bucket::bucket;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut inputs = Vec::new();
    io::stdin().read_to_end(&mut inputs)?;
    if inputs.len() % 16 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial input pair",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in inputs.chunks_exact(16) {
        let dividend = u64::from_le_bytes(row[..8].try_into().unwrap());
        let divisor = u64::from_le_bytes(row[8..].try_into().unwrap());
        let response = match bucket(dividend, divisor) {
            None => [0, 0],
            Some(value) => [1, value],
        };
        output.write_all(&response)?;
    }
    output.flush()
}
