//! Input-only qualification transport, not a recovered native wire format.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use node115_margin_range::{InvalidView, Ring, Row};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 50_000;
const MAX_ROWS: usize = 4096;

fn decimal(text: &str) -> Result<u64, ()> {
    if text.is_empty()
        || (text.len() > 1 && text.as_bytes()[0] == b'0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    text.parse().map_err(|_| ())
}

fn index(text: &str) -> Result<usize, ()> {
    usize::try_from(decimal(text)?).map_err(|_| ())
}

fn nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(()),
    }
}

fn parse_rows(text: &str) -> Result<Vec<Row>, ()> {
    let mut rows = Vec::new();
    if text != "-" {
        for encoded in text.split(',') {
            if rows.len() == MAX_ROWS || encoded.len() != 80 {
                return Err(());
            }
            let mut row = [0; 40];
            for (slot, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
                row[slot] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
            }
            rows.push(row);
        }
    }
    Ok(rows)
}

fn append_rows(output: &mut String, rows: &[Row]) {
    if rows.is_empty() {
        output.push('-');
        return;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        for byte in row {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
}

fn evaluate(input: &[u8]) -> Result<String, ()> {
    if input.len() > MAX_BYTES
        || !input.is_ascii()
        || input.contains(&b'\r')
        || input.contains(&0)
        || (!input.is_empty() && input.last() != Some(&b'\n'))
    {
        return Err(());
    }
    if input.is_empty() {
        return Ok(String::new());
    }
    let text = std::str::from_utf8(input).map_err(|_| ())?;
    let mut seen = HashSet::new();
    let mut output = String::new();
    for (record, line) in text[..text.len() - 1].split('\n').enumerate() {
        if record == MAX_RECORDS {
            return Err(());
        }
        let mut fields = line.split('\t');
        let id = fields.next().ok_or(())?;
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            || !seen.insert(id)
        {
            return Err(());
        }
        let head = index(fields.next().ok_or(())?)?;
        let live = index(fields.next().ok_or(())?)?;
        let exposure = decimal(fields.next().ok_or(())?)?;
        let rows = parse_rows(fields.next().ok_or(())?)?;
        if fields.next().is_some() {
            return Err(());
        }
        match Ring::new(&rows, head, live) {
            Ok(ring) => {
                let range = ring.through(exposure);
                write!(
                    output,
                    "{id}\tok\t{}\t{}\t{}\t",
                    range.included_count,
                    range.first.len(),
                    range.second.len()
                )
                .map_err(|_| ())?;
                if let Some(selected) = range.selected {
                    write!(
                        output,
                        "{}\t{}\t{}\t{}\t{}\t",
                        selected.logical_index,
                        selected.physical_index,
                        selected.key,
                        selected.offset,
                        selected.divisor
                    )
                    .map_err(|_| ())?;
                } else {
                    output.push_str("-\t-\t-\t-\t-\t");
                }
                append_rows(&mut output, range.first);
                output.push('\t');
                append_rows(&mut output, range.second);
                output.push('\n');
            }
            Err(InvalidView::Bounds) => writeln!(output, "{id}\terr\tbounds").map_err(|_| ())?,
            Err(InvalidView::Order) => writeln!(output, "{id}\terr\torder").map_err(|_| ())?,
        }
    }
    Ok(output)
}

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        eprintln!("invalid arguments");
        return ExitCode::from(2);
    }
    let mut input = Vec::new();
    if io::stdin()
        .lock()
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
    {
        eprintln!("input read failed");
        return ExitCode::from(2);
    }
    let output = match evaluate(&input) {
        Ok(output) => output,
        Err(()) => {
            eprintln!("invalid input");
            return ExitCode::from(2);
        }
    };
    let mut stdout = io::stdout().lock();
    if stdout
        .write_all(output.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        eprintln!("output write failed");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
