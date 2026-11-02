//! Input-only harness for authored Rust; no expected bytes or file access.
use node94_alias::key_hash;
use std::io::{self, Read, Write};

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], &'static str> {
    if input.len() < n {
        return Err("record");
    }
    let (result, rest) = input.split_at(n);
    *input = rest;
    Ok(result)
}

fn run(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() < 7 || &raw[..5] != b"KH94\x01" {
        return Err("header");
    }
    let count = u16::from_le_bytes(raw[5..7].try_into().unwrap());
    let mut input = &raw[7..];
    let mut output = raw[..7].to_vec();
    for _ in 0..count {
        let header = take(&mut input, 22)?;
        let id = u16::from_le_bytes(header[..2].try_into().unwrap());
        let seed = [
            u64::from_le_bytes(header[2..10].try_into().unwrap()),
            u64::from_le_bytes(header[10..18].try_into().unwrap()),
        ];
        let length = u32::from_le_bytes(header[18..22].try_into().unwrap()) as usize;
        let key = take(&mut input, length).map_err(|_| "payload")?;
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(&key_hash(seed, key).to_le_bytes());
        for extra_capacity in [0, 1, 16] {
            let mut copied = Vec::with_capacity(length + extra_capacity);
            copied.extend_from_slice(key);
            if length != 0 && copied.as_ptr() == key.as_ptr() {
                return Err("copied storage");
            }
            output.extend_from_slice(&key_hash(seed, &copied).to_le_bytes());
        }
    }
    if !input.is_empty() {
        return Err("trailing");
    }
    Ok(output)
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    match run(&input) {
        Ok(output) => io::stdout().write_all(&output).unwrap(),
        Err(reason) => {
            eprintln!("key-hash driver: {reason}");
            std::process::exit(1);
        }
    }
}
