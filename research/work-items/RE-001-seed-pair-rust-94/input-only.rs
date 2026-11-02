//! Authored input-only factory/composition harness; no expected fixture access.
use node94_alias::{key_hash, next_seed_pair};
use std::io::{self, Read, Write};

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], &'static str> {
    if input.len() < n { return Err("record"); }
    let (part, rest) = input.split_at(n);
    *input = rest;
    Ok(part)
}

fn run(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() < 7 || &raw[..5] != b"NS94\x01" { return Err("header"); }
    let count = u16::from_le_bytes(raw[5..7].try_into().unwrap());
    let mut input = &raw[7..];
    let mut output = raw[..7].to_vec();
    for _ in 0..count {
        let header = take(&mut input, 22)?;
        let id = u16::from_le_bytes(header[..2].try_into().unwrap());
        let mut source = [
            u64::from_le_bytes(header[2..10].try_into().unwrap()),
            u64::from_le_bytes(header[10..18].try_into().unwrap()),
        ];
        let length = u32::from_le_bytes(header[18..22].try_into().unwrap()) as usize;
        let key = take(&mut input, length).map_err(|_| "payload")?;
        let installed = next_seed_pair(&mut source);
        let first = key_hash(installed, key);
        let second = key_hash(installed, key);
        output.extend_from_slice(&id.to_le_bytes());
        for word in [installed[0], installed[1], source[0], source[1], first, second] {
            output.extend_from_slice(&word.to_le_bytes());
        }
    }
    if !input.is_empty() { return Err("trailing"); }
    Ok(output)
}

fn main() {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    match run(&raw) {
        Ok(output) => io::stdout().write_all(&output).unwrap(),
        Err(reason) => { eprintln!("seed-pair driver: {reason}"); std::process::exit(1); }
    }
}
