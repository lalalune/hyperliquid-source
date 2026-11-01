//! Read input images only; invoke newly authored Rust and emit complete images.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 546 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial input record",
        ));
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(546) {
        let length = usize::from(u16::from_le_bytes(row[32..34].try_into().unwrap()));
        if length > 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "image exceeds backing storage",
            ));
        }
        let mut image: [u8; 512] = row[34..].try_into().unwrap();
        let result = node94_indexed_accumulator::accumulate(
            &mut image[..length],
            word(&row[..8]),
            word(&row[8..16]),
            word(&row[16..24]),
            word(&row[24..32]),
        );
        let (tag, value) = match result {
            Ok(value) => (0, value),
            Err(error) => (error as u8, 0),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)
}
