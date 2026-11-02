//! Test driver: inputs on stdin, actual library results on stdout; no answers.
use std::io::{Read, Write};
use std::process::ExitCode;

fn run() -> Result<(), &'static str> {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data).map_err(|_| "input")?;
    if data.len() < 7 || &data[..5] != b"IC94\x01" {
        return Err("header");
    }
    let count = u16::from_le_bytes([data[5], data[6]]);
    let mut position = 7;
    let mut output = data[..7].to_vec();
    for _ in 0..count {
        if position + 3 > data.len() {
            return Err("record");
        }
        let id = [data[position], data[position + 1]];
        let length = usize::from(data[position + 2]);
        position += 3;
        if position + length > data.len() {
            return Err("payload");
        }
        let carrier = node94_alias::inline_carrier(&data[position..position + length]);
        position += length;
        output.extend_from_slice(&id);
        output.push(u8::from(carrier.is_some()));
        let value = carrier.unwrap_or(0);
        output.extend_from_slice(&(value as u64).to_le_bytes());
        output.extend_from_slice(&((value >> 64) as u64).to_le_bytes());
    }
    if position != data.len() {
        return Err("trailing");
    }
    std::io::stdout().write_all(&output).map_err(|_| "output")
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("inline-carrier driver: {message}");
            ExitCode::FAILURE
        }
    }
}
