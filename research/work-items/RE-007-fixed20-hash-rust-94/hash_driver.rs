//! Input-only authored-Rust comparison driver. No expected answers or names.
#![forbid(unsafe_code)]
use node94_margin_risk::hash20::table_hash20;
use std::io::{self, Read, Write};

fn run(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() < 12 || &raw[..8] != b"K20IN001" {
        return Err("input header");
    }
    let count = u32::from_le_bytes(raw[8..12].try_into().map_err(|_| "count width")?);
    if count > 4096 || raw.len() != 12 + count as usize * 40 {
        return Err("input extent");
    }
    let mut output = Vec::with_capacity(12 + count as usize * 12);
    output.extend_from_slice(b"K20OUT01");
    output.extend_from_slice(&count.to_le_bytes());
    for frame in raw[12..].chunks_exact(40) {
        let id = &frame[..4];
        let k0 = u64::from_le_bytes(frame[4..12].try_into().map_err(|_| "k0 width")?);
        let k1 = u64::from_le_bytes(frame[12..20].try_into().map_err(|_| "k1 width")?);
        let query: [u8; 20] = frame[20..].try_into().map_err(|_| "query width")?;
        let hash = table_hash20([k0, k1], &query);
        output.extend_from_slice(id);
        output.extend_from_slice(&hash.to_le_bytes());
    }
    Ok(output)
}

fn main() {
    let mut raw = Vec::new();
    let result = io::stdin()
        .read_to_end(&mut raw)
        .map_err(|_| "stdin read failed")
        .and_then(|_| run(&raw));
    match result {
        Ok(output) => {
            if let Err(error) = io::stdout().write_all(&output) {
                eprintln!("stdout write failed: {error}");
                std::process::exit(2);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
