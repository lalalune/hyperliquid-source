use node94_wide_subtract::image::subtract_into_image;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 282 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial wide-subtract input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(282) {
        let offset = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap()) as usize;
        let length = usize::from(u16::from_le_bytes(row[24..26].try_into().unwrap()));
        if length > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid image length",
            ));
        }
        let mut image: [u8; 256] = row[26..].try_into().unwrap();
        let (tag, value) =
            match subtract_into_image(&mut image[..length], offset(0), offset(8), offset(16)) {
                Ok(value) => (0, value),
                Err(_) => (1, 0),
            };
        output.write_all(&[tag])?;
        output.write_all(&value.to_le_bytes())?;
        output.write_all(&image)?;
    }
    output.flush()
}
