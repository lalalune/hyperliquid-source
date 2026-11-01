use node94_tag_exchange::exchange;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU8, Ordering};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 24 != 0 {
        return Err("partial tag-exchange input".into());
    }
    let mut output = Vec::with_capacity(input.len() / 24 * 32);
    for row in input.chunks_exact(24) {
        let tag = u64::from_le_bytes(row[0..8].try_into()?);
        let object = u64::from_le_bytes(row[8..16].try_into()?);
        let old = u64::from_le_bytes(row[16..24].try_into()?);
        if old > 255 {
            return Err("invalid tag-exchange descriptor".into());
        }
        let cell = AtomicU8::new(old as u8);
        let result = exchange(tag, object, &cell);
        for value in [
            result.rax,
            result.rcx,
            result.field_address,
            u64::from(cell.load(Ordering::SeqCst)),
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
