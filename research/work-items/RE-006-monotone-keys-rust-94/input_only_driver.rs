//! Input-only client for the separately compiled existing orderbook library.
extern crate node94_orderbook;

use node94_orderbook::monotone_keys::{QualifiedOrdering, Unsupported, normalize};
use std::io::{self, Read, Write};

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    assert_eq!(&magic, b"M94IN001");
    let cases = read_u32(&mut input)?;
    output.write_all(b"M94OUT01")?;
    output.write_all(&cases.to_le_bytes())?;

    for _ in 0..cases {
        let id = read_u32(&mut input)?;
        let count = read_u32(&mut input)?;
        assert!(count <= 4097);
        let mut words = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut bytes = [0; 8];
            input.read_exact(&mut bytes)?;
            words.push(u64::from_le_bytes(bytes));
        }
        let status = match normalize(&mut words) {
            Ok(QualifiedOrdering::Nondecreasing) => 0,
            Ok(QualifiedOrdering::StrictlyDecreasing) => 1,
            Err(Unsupported::Length) => 2,
            Err(Unsupported::Ordering) => 3,
        };
        output.write_all(&id.to_le_bytes())?;
        output.write_all(&[status])?;
        output.write_all(&count.to_le_bytes())?;
        for word in words {
            output.write_all(&word.to_le_bytes())?;
        }
    }
    let mut trailing = [0];
    assert_eq!(input.read(&mut trailing)?, 0);
    output.flush()
}
