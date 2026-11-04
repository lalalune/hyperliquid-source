//! Input-only validation transport; not a recovered native wire format.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use node115_stake_predicate::{InvalidView, Row, predicate};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 8192;
const MAX_ROWS: usize = 4096;
const MAX_KEYS: usize = 4096;

fn decimal(text: &str) -> Result<u64, ()> {
    if text.is_empty()
        || (text.len() > 1 && text.as_bytes()[0] == b'0')
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    text.parse().map_err(|_| ())
}

fn metadata(text: &str) -> Result<usize, ()> {
    usize::try_from(decimal(text)?).map_err(|_| ())
}

fn key(text: &str) -> Result<[u8; 20], ()> {
    if text.len() != 40 {
        return Err(());
    }
    fn nibble(byte: u8) -> Result<u8, ()> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(()),
        }
    }
    let mut result = [0; 20];
    for (place, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        result[place] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(result)
}

fn rows(text: &str, capacity: usize) -> Result<Vec<Row>, ()> {
    if capacity > MAX_ROWS {
        return Err(());
    }
    let mut result = Vec::with_capacity(capacity);
    if text != "-" {
        for field in text.split(',') {
            if result.len() == capacity {
                return Err(());
            }
            let (encoded_key, weight) = field.split_once(':').ok_or(())?;
            result.push(Row {
                key: key(encoded_key)?,
                weight: decimal(weight)?,
            });
        }
    }
    if result.len() != capacity {
        return Err(());
    }
    Ok(result)
}

fn keys(text: &str) -> Result<Vec<[u8; 20]>, ()> {
    let mut result = Vec::new();
    if text != "-" {
        for field in text.split(',') {
            if result.len() == MAX_KEYS {
                return Err(());
            }
            result.push(key(field)?);
        }
    }
    Ok(result)
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
    for (index, line) in text[..text.len() - 1].split('\n').enumerate() {
        if index == MAX_RECORDS {
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
        let capacity = metadata(fields.next().ok_or(())?)?;
        let head = metadata(fields.next().ok_or(())?)?;
        let live = metadata(fields.next().ok_or(())?)?;
        let physical = rows(fields.next().ok_or(())?, capacity)?;
        let selected = keys(fields.next().ok_or(())?)?;
        if fields.next().is_some() {
            return Err(());
        }
        match predicate(&physical, head, live, &selected) {
            Ok(observation) => writeln!(
                output,
                "{id}\tok\t{}\t{}\t{}",
                observation.selected_sum,
                observation.total_sum,
                u8::from(observation.passes)
            ),
            Err(InvalidView::Bounds) => writeln!(output, "{id}\tbounds"),
            Err(InvalidView::Order) => writeln!(output, "{id}\torder"),
        }
        .map_err(|_| ())?;
    }
    Ok(output)
}

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        eprintln!("invalid arguments");
        return ExitCode::from(2);
    }
    if usize::BITS != 64 {
        eprintln!("64-bit host required");
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
