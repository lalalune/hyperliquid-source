use std::io::{self, Read, Write};

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 44 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial lookup input",
        ));
    }
    let mut output = Vec::with_capacity(input.len() / 44 * 8);
    for row in input.chunks_exact(44) {
        let value = u128::from(word(&row[..8])) | (u128::from(word(&row[8..16])) << 64);
        let seed = word(&row[16..24]);
        let step = word(&row[24..32]);
        let index = u32::from_le_bytes(row[32..36].try_into().unwrap()) as usize;
        if index >= 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid table override",
            ));
        }
        let mut table = core::array::from_fn(|i| seed.wrapping_add(step.wrapping_mul(i as u64)));
        table[index] = word(&row[36..44]);
        output.extend_from_slice(&node94_bsr_table::lookup(value, &table).to_le_bytes());
    }
    io::stdout().write_all(&output)
}
