//! Input-only client: expected arrays and indices remain outside this process.
use node94_orderbook::first_left_insertion::insert_loaded;
use std::io::{self, Read, Write};

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    assert_eq!(&magic, b"I8IN0001");
    let count = read_u32(&mut input)?;
    output.write_all(b"I8OUT001")?;
    output.write_all(&count.to_le_bytes())?;
    for _ in 0..count {
        let id = read_u32(&mut input)?;
        let value = read_u64(&mut input)?;
        let mut words = [0; 9];
        for word in &mut words {
            *word = read_u64(&mut input)?;
        }
        let index = insert_loaded(&mut words, value);
        output.write_all(&id.to_le_bytes())?;
        output.write_all(&(index as u32).to_le_bytes())?;
        for word in words {
            output.write_all(&word.to_le_bytes())?;
        }
    }
    let mut trailing = [0];
    assert_eq!(input.read(&mut trailing)?, 0);
    output.flush()
}
