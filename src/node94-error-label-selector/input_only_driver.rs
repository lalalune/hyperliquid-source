//! Input-only client: expected results and captured instruction bytes are absent.
use node94_error_label_selector::{captured_bytes, select};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    if input.len() % 805 != 0 {
        return Err("partial input record".into());
    }
    let mut output = Vec::new();
    for row in input.chunks_exact(805) {
        let bias = u64::from_le_bytes(row[..8].try_into()?);
        let tag = row[8];
        let window: &[u8; 796] = row[9..].try_into()?;
        let r = select(tag, bias);
        for word in [r.rax, r.rdx, r.rcx, r.rsi] {
            output.extend_from_slice(&word.to_le_bytes());
        }
        let bytes = captured_bytes(tag, window);
        output.extend_from_slice(bytes);
        output.resize(output.len() + 779 - bytes.len(), 0);
    }
    io::stdout().write_all(&output)?;
    Ok(())
}
