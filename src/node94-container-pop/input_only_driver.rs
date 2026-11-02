//! Input-only native client; it contains no expected answers.
use node94_container_pop::{transition, AccessError};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 274 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(274) {
        if u16::from_le_bytes(row[16..18].try_into()?) > 256 {
            return Err("image length exceeds backing storage".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(274) {
        let base = u64::from_le_bytes(row[..8].try_into()?);
        let object = u64::from_le_bytes(row[8..16].try_into()?);
        let length = usize::from(u16::from_le_bytes(row[16..18].try_into()?));
        let mut image: [u8; 256] = row[18..].try_into()?;
        let (tag, value) = match transition(&mut image[..length], base, object) {
            Ok(value) => (0, value),
            Err(error) => (
                match error {
                    AccessError::ImageRange => 1,
                    AccessError::Current => 2,
                    AccessError::Compare => 3,
                    AccessError::Top => 4,
                    AccessError::Popped => 5,
                    AccessError::Output => 6,
                },
                0,
            ),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
