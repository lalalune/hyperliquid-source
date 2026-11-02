use node94_round_modes::{RoundingMode, round_bits};
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 9 != 0 || input.chunks_exact(9).any(|row| row[8] > 3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid input framing or RC byte",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(9) {
        let bits = u64::from_le_bytes(row[..8].try_into().unwrap());
        let mode = match row[8] {
            0 => RoundingMode::NearestEven,
            1 => RoundingMode::TowardNegative,
            2 => RoundingMode::TowardPositive,
            _ => RoundingMode::TowardZero,
        };
        output.write_all(&round_bits(bits, mode).to_le_bytes())?;
    }
    output.flush()
}
