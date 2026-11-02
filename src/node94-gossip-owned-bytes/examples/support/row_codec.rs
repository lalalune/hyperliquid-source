//! Input-only adapters. Expected records never enter this module.

use node94_gossip_owned_bytes::{
    Budget, Failure, HeaderFault, decode_owned_bytes, validate_bytes,
};
use std::io;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn identifier(text: &str) -> io::Result<&str> {
    if text.is_empty()
        || text.len() > 64
        || !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(invalid("invalid case identifier"));
    }
    Ok(text)
}

fn decimal(text: &str) -> io::Result<u64> {
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid("expected canonical decimal u64"));
    }
    text.parse().map_err(|_| invalid("decimal exceeds u64"))
}

fn unhex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid("odd hexadecimal length"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => Ok(high * 16 + low),
                _ => Err(invalid("expected lowercase hexadecimal bytes")),
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("formatting into owned String");
    }
    output
}

fn number<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

fn bytes_or_null(value: Option<&[u8]>) -> String {
    value.map_or_else(|| "null".to_owned(), |raw| format!("\"{}\"", hex(raw)))
}

pub fn validator_row(line: &str) -> io::Result<String> {
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() != 3 {
        return Err(invalid("expected id,origin_mod8,input_hex"));
    }
    let id = identifier(fields[0])?;
    let residue = usize::try_from(decimal(fields[1])?).map_err(|_| invalid("origin width"))?;
    if residue >= 8 {
        return Err(invalid("origin_mod8 must be below8"));
    }
    let raw = unhex(fields[2])?;
    let capacity = raw.len().checked_add(8).ok_or_else(|| invalid("input too large"))?;
    let mut storage = vec![0; capacity];
    let offset = (residue + 8 - (storage.as_ptr() as usize & 7)) & 7;
    storage[offset..offset + raw.len()].copy_from_slice(&raw);
    let input = &storage[offset..offset + raw.len()];
    if input.as_ptr() as usize & 7 != residue {
        return Err(invalid("actual input alignment differs"));
    }
    let (tag, valid_up_to, error_len, validated) = match validate_bytes(input) {
        Ok(()) => (0, None, None, Some(input)),
        Err(error) => (1, Some(error.valid_up_to), error.error_len, None),
    };
    Ok(format!(
        "{{\"error_len\":{},\"id\":\"{id}\",\"tag\":{tag},\"valid_up_to\":{},\"validated_hex\":{}}}",
        number(error_len), number(valid_up_to), bytes_or_null(validated)
    ))
}

pub fn wire_row(line: &str) -> io::Result<String> {
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() != 5 {
        return Err(invalid("expected id,mode,counter,limit,wire_hex"));
    }
    let id = identifier(fields[0])?;
    let mut budget = Budget {
        mode_word: decimal(fields[1])?,
        counter: decimal(fields[2])?,
        limit: decimal(fields[3])?,
    };
    let wire = unhex(fields[4])?;
    let mut input = wire.as_slice();
    let outcome = decode_owned_bytes(&mut input, &mut budget);
    let mut needed = None;
    let mut expected = None;
    let mut found = None;
    let mut valid_up_to = None;
    let mut error_len = None;
    let mut data = None;
    let (tag, phase) = match &outcome.result {
        Ok(value) => {
            data = Some(value.as_bytes());
            (18, "ok")
        }
        Err(Failure::Header(HeaderFault::Budget)) => (2, "header_error"),
        Err(Failure::Header(HeaderFault::Need { additional })) => {
            needed = Some(*additional);
            (0, "header_error")
        }
        Err(Failure::Header(HeaderFault::Type { expected: e, found: f })) => {
            expected = Some(*e);
            found = Some(*f);
            (3, "header_error")
        }
        Err(Failure::PayloadBudget) => (2, "payload_budget"),
        Err(Failure::PayloadUnavailable) => (1, "payload_short"),
        Err(Failure::InvalidUtf8(error)) => {
            valid_up_to = Some(error.valid_up_to);
            error_len = error.error_len;
            (6, "invalid_utf8")
        }
    };
    let stores = outcome.counter_stores.as_slice().iter().map(u64::to_string).collect::<Vec<_>>().join(",");
    Ok(format!(
        "{{\"consumed\":{},\"counter_after\":{},\"counter_writes\":[{}],\"data_hex\":{},\"error_len\":{},\"expected\":{},\"found\":{},\"id\":\"{id}\",\"needed\":{},\"phase\":\"{phase}\",\"release_request_length\":{},\"remaining\":{},\"tag\":{tag},\"tail_hex\":\"{}\",\"valid_up_to\":{}}}",
        wire.len() - input.len(), budget.counter, stores, bytes_or_null(data), number(error_len),
        number(expected), number(found), number(needed), number(outcome.release_request_length),
        input.len(), hex(input), number(valid_up_to)
    ))
}
