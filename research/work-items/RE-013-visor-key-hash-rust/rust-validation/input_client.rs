//! Input-only client: no expected values, fixtures, oracle or filesystem reads.
use std::io::{self, BufWriter, Read, Write};
use visor_key_hash::hash_key;

fn lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn seed_word(text: &str) -> Result<u64, String> {
    if text.len() != 16 || !lower_hex(text) {
        return Err("seed must have sixteen lowercase hex digits".into());
    }
    u64::from_str_radix(text, 16).map_err(|_| "seed range".into())
}

fn input_bytes(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.is_empty() || !text.len().is_multiple_of(2) || !lower_hex(text) {
        return Err("noncanonical input byte hex".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "hex text")?;
            u8::from_str_radix(text, 16).map_err(|_| "hex byte".into())
        })
        .collect()
}

fn run() -> Result<(), String> {
    if std::env::args().len() != 1 {
        return Err("client accepts no arguments".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    if input.is_empty() {
        return Err("empty input stream".into());
    }
    let mut writer = BufWriter::new(io::stdout().lock());
    for (index, line) in input.split_inclusive('\n').enumerate() {
        let line = line.strip_suffix('\n').ok_or("missing LF")?;
        let fields: Vec<_> = line.split('\t').collect();
        let id = format!("c{index:06}");
        if fields.len() != 4 || fields[0] != id {
            return Err("input fields or ordered opaque ID".into());
        }
        let seed = [seed_word(fields[1])?, seed_word(fields[2])?];
        let bytes = input_bytes(fields[3])?;
        let result = hash_key(seed, &bytes);
        writeln!(writer, "{id}\t{result:016x}").map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("invalid fixture: {error}");
        std::process::exit(2);
    }
}
