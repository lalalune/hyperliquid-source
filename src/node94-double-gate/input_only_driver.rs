//! Input-only native client: numeric image, object and original comparison mode.
use node94_double_gate::{compare, CompareMode, Refusal};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 147 != 0 {
        return Err("partial input record".into());
    }
    for row in input.chunks_exact(147) {
        if row[16] > 7 || u16::from_le_bytes(row[17..19].try_into()?) > 128 {
            return Err("invalid image/mode descriptor".into());
        }
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(147) {
        let word = |at| u64::from_le_bytes(row[at..at + 8].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(row[17..19].try_into()?));
        let mode = CompareMode {
            invalid_masked: row[16] & 1 != 0,
            denormal_masked: row[16] & 2 != 0,
            denormals_are_zero: row[16] & 4 != 0,
        };
        let (tag, value) = match compare(&row[19..19 + length], word(0), word(8), mode) {
            Ok(value) => (0, value),
            Err(Refusal::ImageRange) => (1, 0),
            Err(Refusal::PointerField) => (2, 0),
            Err(Refusal::Payload) => (3, 0),
            Err(Refusal::InvalidOperationUnmasked) => (4, 0),
            Err(Refusal::DenormalOperandUnmasked) => (5, 0),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
