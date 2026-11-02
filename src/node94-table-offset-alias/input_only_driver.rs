use std::io::{self, Read, Write};

fn word(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 370 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial table-offset input",
        ));
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(370) {
        let length = u16::from_le_bytes(row[48..50].try_into().unwrap()) as usize;
        if length > 320 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "image length exceeds record",
            ));
        }
        let mut image: [u8; 320] = row[50..].try_into().unwrap();
        let result = node94_table_offset_alias::apply(
            &mut image[..length],
            word(&row[..8]),
            word(&row[8..16]),
            word(&row[16..24]),
            word(&row[24..32]),
            word(&row[32..40]),
            word(&row[40..48]),
        );
        let (tag, value) = match result {
            Ok(value) => (0, value),
            Err(error) => (
                match error {
                    node94_table_offset_alias::AccessError::ImageRange => 1,
                    node94_table_offset_alias::AccessError::StateBounds => 2,
                    node94_table_offset_alias::AccessError::OutputBounds => 3,
                    node94_table_offset_alias::AccessError::TableBounds => 4,
                },
                0,
            ),
        };
        output.push(tag);
        output.extend_from_slice(&value.to_le_bytes());
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output)
}
