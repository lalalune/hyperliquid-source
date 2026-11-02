//! Input-only wire client. Chosen serialization/status fields are not native ABI.
use node94_orderbook::n21_outer_admission::first_short_run21;
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() != 76 * 22 * 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected76 literal input records"));
    }
    let mut output = Vec::with_capacity(76 * 27 * 8);
    for record in input.chunks_exact(22 * 8) {
        let loaded: Vec<u64> = record.chunks_exact(8)
            .map(|word| u64::from_le_bytes(word.try_into().unwrap())).collect();
        let words: [u64; 21] = loaded[..21].try_into().unwrap();
        let result = first_short_run21(&words, loaded[21]);
        for word in words {
            output.extend_from_slice(&word.to_le_bytes());
        }
        let (admitted, count, capacity, context) = match result.request {
            Some(request) => (1_u64, request.word_count, request.scratch_capacity_qwords, request.opaque_context),
            None => (0, 0, 0, 0),
        };
        for field in [admitted, result.natural_run as u64, u64::from(result.ascending), count, capacity, context] {
            output.extend_from_slice(&field.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)
}
