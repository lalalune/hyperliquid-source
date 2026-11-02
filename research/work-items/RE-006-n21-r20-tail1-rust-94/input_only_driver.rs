//! Input-only synthetic wire client; chosen framing/status is not native ABI.
use node94_orderbook::n21_run20_tail1::{Side, project_first_run20};
use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() != 11028 || &input[..8] != b"R20IN001" || u32::from_le_bytes(input[8..12].try_into().unwrap()) != 54 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected54 fixed input records"));
    }
    let mut output = b"R20OUT01".to_vec();
    output.extend_from_slice(&54_u32.to_le_bytes());
    for (index, record) in input[12..].chunks_exact(204).enumerate() {
        let id = u32::from_le_bytes(record[..4].try_into().unwrap());
        if id as usize != index {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "input record order"));
        }
        let loaded: Vec<u64> = record[4..].chunks_exact(8)
            .map(|raw| u64::from_le_bytes(raw.try_into().unwrap())).collect();
        let mut words: [u64; 21] = loaded[..21].try_into().unwrap();
        let mut scratch: [u64; 4] = loaded[21..].try_into().unwrap();
        let (status, post_normalization, metadata, stores) = match project_first_run20(&mut words, &mut scratch) {
            Ok(value) => (0_u32, value.post_normalization21, [value.natural_run as u64, u64::from(value.ascending),
                value.upper_bound_index as u64, value.loop_stores.len() as u64, value.reversal_word_writes as u64,
                value.first_copy_bytes as u64, value.terminal_copy_destination_index as u64,
                value.terminal_copy_bytes as u64, value.copy_call_count as u64], value.loop_stores),
            Err(value) => (1, words, [value.natural_run as u64, u64::from(value.ascending), 0, 0, 0, 0, 0, 0, 0], Vec::new()),
        };
        if stores.len() > 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "store observation bound"));
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&status.to_le_bytes());
        let mut fields = Vec::with_capacity(235);
        fields.extend(words);
        fields.extend(scratch);
        fields.extend(post_normalization);
        fields.extend(metadata);
        for event in stores {
            fields.extend([event.output_index as u64, event.word, event.compared_left_index as u64,
                event.compared_left_word, event.compared_tail_word, u64::from(event.loaded_bits_provider == Side::Tail),
                u64::from(event.retired_cursor == Side::Tail), event.left_remaining_after as u64, event.tail_remaining_after as u64]);
        }
        fields.resize(235, 0);
        for field in fields {
            output.extend_from_slice(&field.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)
}
