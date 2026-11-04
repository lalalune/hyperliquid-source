// SPDX-License-Identifier: MIT
//! Input-only host protocol. No expected data, artifacts or native pointers.

#![forbid(unsafe_code)]

use node115_rpc_flat_materializer::{RingView, Row, SearchResult};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{self, Read, Write};

const MAX_BYTES: usize = 16_777_216;
const MAX_RECORDS: usize = 16_384;
const MAX_CAPACITY: usize = 256;
const MAX_QUERIES: usize = 32;

type InputResult<T> = Result<T, &'static str>;

fn decimal(text: &str) -> InputResult<usize> {
    let raw = text.as_bytes();
    if raw.is_empty() || (raw.len() > 1 && raw[0] == b'0') || !raw.iter().all(u8::is_ascii_digit) {
        return Err("noncanonical unsigned decimal");
    }
    raw.iter()
        .try_fold(0usize, |value, byte| {
            value
                .checked_mul(10)?
                .checked_add(usize::from(*byte - b'0'))
        })
        .ok_or("unsigned decimal out of range")
}

fn digit(byte: u8) -> InputResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("expected lowercase hexadecimal"),
    }
}

fn hex<const N: usize>(text: &str) -> InputResult<[u8; N]> {
    if text.len() != 2 * N {
        return Err("incorrect hexadecimal width");
    }
    let mut result = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(result)
}

fn physical_rows(text: &str, capacity: usize) -> InputResult<Vec<Row>> {
    if capacity == 0 {
        return if text == "-" {
            Ok(Vec::new())
        } else {
            Err("expected empty rows marker")
        };
    }
    let mut rows = Vec::with_capacity(capacity);
    for record in text.split(',') {
        if rows.len() == capacity {
            return Err("too many physical rows");
        }
        let raw = hex::<40>(record)?;
        let mut key = [0; 32];
        key.copy_from_slice(&raw[..32]);
        let mut value = [0; 8];
        value.copy_from_slice(&raw[32..]);
        rows.push(Row {
            key,
            value: u64::from_be_bytes(value),
        });
    }
    if rows.len() != capacity {
        return Err("physical row count differs from capacity");
    }
    Ok(rows)
}

fn query_keys(text: &str) -> InputResult<Vec<[u8; 32]>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    let mut queries = Vec::new();
    for query in text.split(',') {
        if queries.len() == MAX_QUERIES {
            return Err("query limit exceeded");
        }
        queries.push(hex::<32>(query)?);
    }
    Ok(queries)
}

fn render(input: &[u8]) -> InputResult<String> {
    if input.is_empty() || input.len() > MAX_BYTES || input.last() != Some(&b'\n') {
        return Err("input must be nonempty, bounded and LF-terminated");
    }
    if !input.is_ascii() || input.contains(&b'\r') {
        return Err("input must be ASCII with LF-only endings");
    }
    let text = std::str::from_utf8(input).map_err(|_| "invalid ASCII input")?;
    let mut identifiers = BTreeSet::new();
    let mut output = String::new();
    for (number, line) in text[..text.len() - 1].split('\n').enumerate() {
        if number >= MAX_RECORDS || line.is_empty() {
            return Err("empty record or record limit exceeded");
        }
        let mut fields = line.split('\t');
        let id = fields.next().ok_or("missing case ID")?;
        let operation = fields.next().ok_or("missing operation")?;
        let capacity = fields.next().ok_or("missing capacity")?;
        let head = fields.next().ok_or("missing head")?;
        let length = fields.next().ok_or("missing live length")?;
        let rows = fields.next().ok_or("missing physical rows")?;
        let queries = fields.next().ok_or("missing queries")?;
        if fields.next().is_some() {
            return Err("expected exactly seven fields");
        }
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !identifiers.insert(id)
        {
            return Err("invalid or repeated case ID");
        }
        if operation != "S" && operation != "M" {
            return Err("unknown operation");
        }
        let capacity = decimal(capacity)?;
        let head = decimal(head)?;
        let length = decimal(length)?;
        if capacity > MAX_CAPACITY {
            return Err("capacity limit exceeded");
        }
        let rows = physical_rows(rows, capacity)?;
        let queries = query_keys(queries)?;
        if operation == "S" && queries.len() != 1 {
            return Err("search requires one query");
        }
        let ring = RingView::new(&rows, head, length).map_err(|_| "invalid supplied ring")?;
        if operation == "S" {
            match ring.search(&queries[0]) {
                SearchResult::Found {
                    logical_index,
                    physical_index,
                    value,
                } => {
                    writeln!(
                        output,
                        "{id}\tH\t{logical_index}\t{physical_index}\t{value:016x}"
                    )
                    .map_err(|_| "output formatting failed")?;
                }
                SearchResult::Missing { insertion_index } => {
                    writeln!(output, "{id}\tN\t{insertion_index}")
                        .map_err(|_| "output formatting failed")?;
                }
            }
        } else if let Some(values) = ring.materialize(&queries) {
            write!(output, "{id}\tV\t").map_err(|_| "output formatting failed")?;
            if values.is_empty() {
                output.push('-');
            } else {
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write!(output, "{value:016x}").map_err(|_| "output formatting failed")?;
                }
            }
            output.push('\n');
        } else {
            writeln!(output, "{id}\tF").map_err(|_| "output formatting failed")?;
        }
    }
    Ok(output)
}

fn run() -> InputResult<()> {
    if std::env::args_os().nth(1).is_some() {
        return Err("arguments are not accepted");
    }
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "stdin read failed")?;
    // Nothing is written until every row, ID, resource limit and ring validates.
    let output = render(&input)?;
    io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|_| "stdout write failed")
}

fn main() {
    if let Err(message) = run() {
        let _ = writeln!(io::stderr().lock(), "input driver: {message}");
        std::process::exit(2);
    }
}
