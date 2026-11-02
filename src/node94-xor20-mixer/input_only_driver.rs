use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 44 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial mixer input",
        ));
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for row in input.chunks_exact(44) {
        let prefix = u64::from_le_bytes(row[..8].try_into().unwrap());
        let data: &[u8; 20] = row[8..28].try_into().unwrap();
        let seeds = [
            u64::from_le_bytes(row[28..36].try_into().unwrap()),
            u64::from_le_bytes(row[36..44].try_into().unwrap()),
        ];
        output.write_all(&node94_xor20_mixer::mix(prefix, data, seeds).to_le_bytes())?;
    }
    output.flush()
}
