// SPDX-License-Identifier: MIT
// Input-only transport for independently supplied point-classification cases.
#![forbid(unsafe_code)]

use node115_fee_point_classifier::{MAX_QUANTITY, Point, classify};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::process::ExitCode;

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECORDS: usize = 8192;

fn quantity(field: &[u8]) -> Result<u64, &'static str> {
    if field.is_empty() || (field.len() > 1 && field[0] == b'0') {
        return Err("quantity must be canonical unsigned decimal");
    }
    let mut value = 0_u64;
    for &byte in field {
        if !byte.is_ascii_digit() {
            return Err("quantity must be canonical unsigned decimal");
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or("quantity decimal overflow")?;
    }
    if !(1..=MAX_QUANTITY).contains(&value) {
        return Err("quantity outside admitted domain");
    }
    Ok(value)
}

fn bits(field: &[u8]) -> Result<u64, &'static str> {
    if field.len() != 16 {
        return Err("bit fields must contain exactly 16 lowercase hexadecimal digits");
    }
    let mut value = 0_u64;
    for &byte in field {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err("bit fields must contain exactly 16 lowercase hexadecimal digits"),
        };
        value = (value << 4) | u64::from(digit);
    }
    Ok(value)
}

fn run() -> Result<(), &'static str> {
    if std::env::args_os().count() != 1 {
        return Err("this driver accepts stdin only and no arguments");
    }
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "failed to read stdin")?;
    if input.len() > MAX_BYTES {
        return Err("input exceeds 2 MiB");
    }
    if !input.is_ascii() || input.last() != Some(&b'\n') {
        return Err("nonempty ASCII input with a final LF is required");
    }

    let mut ids = BTreeSet::new();
    let mut output = String::new();
    // Drop exactly the required final LF; an interior empty row remains invalid.
    for (index, line) in input[..input.len() - 1].split(|&b| b == b'\n').enumerate() {
        if index >= MAX_RECORDS {
            return Err("input exceeds 8192 records");
        }
        let fields: Vec<&[u8]> = line.split(|&b| b == b'\t').collect();
        if fields.len() != 8 {
            return Err("each record must contain exactly eight TSV fields");
        }
        let id = fields[0];
        if id.is_empty()
            || !id
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        {
            return Err("case IDs must match [A-Za-z0-9_-]+");
        }
        if !ids.insert(id) {
            return Err("duplicate case ID");
        }
        let point = Point {
            quantity: quantity(fields[1])?,
            scale_bits: bits(fields[2])?,
            t_bits: bits(fields[3])?,
            d_bits: bits(fields[4])?,
            q_bits: bits(fields[5])?,
            m_bits: bits(fields[6])?,
            h_bits: bits(fields[7])?,
        };
        let class = classify(point).map_err(|_| "point outside admitted quantity/scale domain")?;
        output.push_str(std::str::from_utf8(id).map_err(|_| "invalid case ID encoding")?);
        output.push('\t');
        output.push_str(class.as_str());
        output.push('\n');
    }

    // All rows are admitted before the first stdout write. An I/O failure after
    // writing begins may leave partial output; malformed input cannot do so.
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .map_err(|_| "failed to write stdout")?;
    stdout.flush().map_err(|_| "failed to flush stdout")
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("fee-point-driver: {message}");
            ExitCode::from(2)
        }
    }
}
