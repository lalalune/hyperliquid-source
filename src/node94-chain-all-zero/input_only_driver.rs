//! Input-only client for newly authored Rust; no captured code or expected data.
#![forbid(unsafe_code)]
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 530 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial input record",
        ));
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(530) {
        let image_base = u64::from_le_bytes(row[..8].try_into().unwrap());
        let root_slot = u64::from_le_bytes(row[8..16].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[16..18].try_into().unwrap()));
        if length > 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "image exceeds backing storage",
            ));
        }
        let image = &row[18..];
        let (tag, value) =
            match node94_chain_all_zero::all_zero(&image[..length], image_base, root_slot) {
                Ok(value) => (0, u64::from(value)),
                Err(error) => (error as u8, 0),
            };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
        output.extend_from_slice(image);
    }
    io::stdout().write_all(&output)
}
