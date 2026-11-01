//! Input-only line driver; receives no expected outputs or test IDs
//! with semantic meaning. Std allocation belongs to this driver, not the field.

use node94_consensus_admission::qc_recovery_byte::{ChargeState, read_field};
use std::fmt::Write as _;
use std::io::{self, BufRead};

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if text.is_empty() || text.len() % 2 != 0 || !text.is_ascii() {
        return Err("input must be even-length ASCII hex, or '-'".into());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err("input hex must be lowercase".to_string()),
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String");
    }
    encoded
}

fn process(line: &str) -> Result<String, String> {
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() != 5 {
        return Err("expected id, mode, charge, limit, hex-input (five TSV fields)".into());
    }
    let id = fields[0];
    if id.is_empty()
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err("invalid opaque record id".into());
    }
    let mut state = ChargeState {
        mode: fields[1].parse().map_err(|_| "invalid u32 mode")?,
        charge: fields[2].parse().map_err(|_| "invalid u64 charge")?,
        limit: fields[3].parse().map_err(|_| "invalid u64 limit")?,
    };
    let storage = decode_hex(fields[4])?;
    let mut input = storage.as_slice();
    let result = read_field(&mut state, &mut input);
    let consumed = storage.len() - input.len();
    let (status, value, kind, error_word) = match result {
        Ok(byte) => ("ok", byte.to_string(), "-".to_string(), "-".to_string()),
        Err(error) => (
            "error",
            "-".to_string(),
            error.observed_kind().to_string(),
            error.observed_error_word().to_string(),
        ),
    };
    Ok(format!(
        "{id}\t{status}\t{}\t{consumed}\t{}\t{}\t{value}\t{kind}\t{error_word}",
        state.charge,
        input.len(),
        encode_hex(input),
    ))
}

fn main() {
    for (index, line) in io::stdin().lock().lines().enumerate() {
        let output = line.map_err(|error| error.to_string()).and_then(|line| process(&line));
        match output {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("input line {}: {error}", index + 1);
                std::process::exit(2);
            }
        }
    }
}
