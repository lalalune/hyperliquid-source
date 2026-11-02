#![forbid(unsafe_code)]

use node94_signed_varint_i64::{read_i64, ReaderError};
use std::io::{self, Write};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let path = args.next().ok_or("one stimulus path required")?;
    if args.next().is_some() { return Err("only one stimulus path is accepted".into()); }
    let stimulus = std::fs::read_to_string(path)?;
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in stimulus.lines() {
        let fields: Vec<_> = line.split('|').collect();
        if fields.len() != 4 { return Err("exactly four raw fields required".into()); }
        let id = fields[0];
        if id.is_empty() || id.len() > 64 || !id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            return Err("invalid opaque ASCII id".into());
        }
        if fields[1].is_empty() || !fields[1].bytes().all(|c| c.is_ascii_digit()) {
            return Err("raw DL must be decimal0..255".into());
        }
        let flag: u8 = fields[1].parse()?;
        let encoded = fields[2];
        if encoded.len() > 8192 || encoded.len() % 2 != 0 || !encoded.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err("bounded complete lowercase wire hex required".into());
        }
        let bytes: Vec<u8> = encoded.as_bytes().chunks_exact(2).map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
        }).collect::<Result<_, _>>()?;
        let calls: usize = fields[3].parse()?;
        if !(1..=4).contains(&calls) { return Err("calls must be1..4".into()); }
        let mut input = bytes.as_slice();
        for call in 1..=calls {
            let before = input.len();
            let (tag, value, bits, additional, expected, found) = match read_i64(&mut input, flag) {
                Ok(value) => (18, value.to_string(), format!("\"{:016x}\"", value as u64), "null".into(), "null".into(), "null".into()),
                Err(ReaderError::UnexpectedEnd { needed }) => (0, "null".into(), "null".into(), needed.to_string(), "null".into(), "null".into()),
                Err(ReaderError::InvalidIntegerType { expected_code, found_code }) => (3, "null".into(), "null".into(), "null".into(), expected_code.to_string(), found_code.to_string()),
            };
            writeln!(output, "{{\"additional\":{additional},\"bits\":{bits},\"call\":{call},\"consumed\":{},\"cursor\":{},\"expected\":{expected},\"found\":{found},\"id\":\"{id}\",\"remaining\":{},\"tag\":{tag},\"tail\":\"{}\",\"value\":{value}}}",
                before - input.len(), bytes.len() - input.len(), input.len(), hex(input))?;
        }
    }
    output.flush()?;
    Ok(())
}
