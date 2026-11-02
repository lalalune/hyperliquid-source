//! Input-only client for two separately tagged point relations.
use node94_orderbook::j9_first_front::{FrontSide, insert_j9_loaded, write_first_front};
use std::io::{self, Read, Write};

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut raw = [0; 4];
    input.read_exact(&mut raw)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut raw = [0; 8];
    input.read_exact(&mut raw)?;
    Ok(u64::from_le_bytes(raw))
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    assert_eq!(&magic, b"J9IN0001");
    let count = read_u32(&mut input)?;
    output.write_all(b"J9OUT001")?;
    output.write_all(&count.to_le_bytes())?;
    for _ in 0..count {
        let id = read_u32(&mut input)?;
        let kind = read_u32(&mut input)?;
        let loaded = read_u64(&mut input)?;
        let mut first_output = read_u64(&mut input)?;
        let mut scratch = [0; 21];
        for word in &mut scratch {
            *word = read_u64(&mut input)?;
        }
        let (index, side) = match kind {
            0 => {
                let window: &mut [u64; 10] = (&mut scratch[..10]).try_into().unwrap();
                (insert_j9_loaded(window, loaded) as u32, 2)
            }
            1 => {
                let selected = write_first_front(&mut first_output, scratch[0], scratch[10]);
                (u32::MAX, if selected == FrontSide::Left { 0 } else { 1 })
            }
            _ => panic!("unknown input operation"),
        };
        for word in [id, kind, index, side] {
            output.write_all(&word.to_le_bytes())?;
        }
        output.write_all(&first_output.to_le_bytes())?;
        for word in scratch {
            output.write_all(&word.to_le_bytes())?;
        }
    }
    let mut trailing = [0];
    assert_eq!(input.read(&mut trailing)?, 0);
    output.flush()
}
