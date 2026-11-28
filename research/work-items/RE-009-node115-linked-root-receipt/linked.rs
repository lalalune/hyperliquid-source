use node115_abci_blake3::{Blake3Hasher, blake3_hash};
use std::error::Error;
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn Error>> {
    let raw = std::env::args().nth(1).ok_or("expected raw ABCI digest")?;
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("raw ABCI digest must be 32 bytes of hex".into());
    }
    let mut hex_bytes = [0_u8; 32];
    for (byte, index) in hex_bytes.iter_mut().zip((0..64).step_by(2)) {
        *byte = u8::from_str_radix(&raw[index..index + 2], 16)?;
    }
    let mut state = Blake3Hasher::new();
    let mut stream = io::stdin().lock();
    let mut chunk = [0_u8; 65536];
    loop {
        let len = stream.read(&mut chunk)?;
        if len == 0 {
            break;
        }
        state.update(&chunk[..len]);
    }
    let inner = state.finalize();
    let mut linked_preimage = [0_u8; 64];
    linked_preimage[..32].copy_from_slice(&inner);
    linked_preimage[32..].copy_from_slice(&hex_bytes);
    let mut output = io::stdout().lock();
    for digest in [inner, blake3_hash(&linked_preimage)] {
        write!(output, "0x")?;
        for byte in digest {
            write!(output, "{byte:02x}")?;
        }
        writeln!(output)?;
    }
    Ok(())
}
