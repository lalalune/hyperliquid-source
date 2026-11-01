use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 14 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial equality input",
        ));
    }
    let mut output = Vec::with_capacity(input.len() / 14);
    for row in input.chunks_exact(14) {
        let length = u64::from_le_bytes(row[..8].try_into().unwrap());
        let left = row[8..11].try_into().unwrap();
        let right = row[11..14].try_into().unwrap();
        output.push(u8::from(node94_ascii_three::equal(length, left, right)));
    }
    io::stdout().write_all(&output)
}
