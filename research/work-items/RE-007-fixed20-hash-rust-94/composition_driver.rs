//! Input-only composition over supplied seeds and a synthetic logical table.
//! Whole native lookup, seed creation, physical pointers and Once are excluded.
#![forbid(unsafe_code)]
use node94_margin_risk::hash20::table_hash20;
use node94_margin_risk::row_selector::{select_row_after_hash, RowChoice};
use std::io::{self, Read, Write};

fn run(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() < 12 || &raw[..8] != b"K20CMP01" {
        return Err("composition header");
    }
    let count = u32::from_le_bytes(raw[8..12].try_into().map_err(|_| "count width")?);
    if count > 4096 || raw.len() != 12 + count as usize * 720 {
        return Err("composition extent");
    }
    let mut output = Vec::with_capacity(12 + count as usize * 22);
    output.extend_from_slice(b"K20CMO01");
    output.extend_from_slice(&count.to_le_bytes());
    for frame in raw[12..].chunks_exact(720) {
        let seeds = [
            u64::from_le_bytes(frame[4..12].try_into().map_err(|_| "k0 width")?),
            u64::from_le_bytes(frame[12..20].try_into().map_err(|_| "k1 width")?),
        ];
        let late_state = u32::from_le_bytes(frame[20..24].try_into().map_err(|_| "state width")?);
        let capacity = u32::from_le_bytes(frame[24..28].try_into().map_err(|_| "capacity width")?);
        if capacity != 32 {
            return Err("outside fixed composition framing domain");
        }
        let query: [u8; 20] = frame[28..48].try_into().map_err(|_| "query width")?;
        let controls = &frame[48..80];
        let mut keys = [[0u8; 20]; 32];
        for (index, key) in keys.iter_mut().enumerate() {
            key.copy_from_slice(&frame[80 + 20 * index..100 + 20 * index]);
        }
        let hash = table_hash20(seeds, &query);
        let selected = select_row_after_hash(1, hash, controls, &keys, &query, late_state)
            .map_err(|_| "unexpected checked-selector policy refusal")?;
        let (kind, index) = match selected.choice {
            RowChoice::SharedDefault => (0u8, u64::MAX),
            RowChoice::Bucket(index) => (1u8, index as u64),
        };
        output.extend_from_slice(&frame[..4]);
        output.extend_from_slice(&hash.to_le_bytes());
        output.extend_from_slice(&[kind, u8::from(selected.initializer_needed)]);
        output.extend_from_slice(&index.to_le_bytes());
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
