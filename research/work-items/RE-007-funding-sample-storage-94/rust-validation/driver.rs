//! Input-only fixture client. It reads no oracle, expected output or files.
use node94_funding_record_storage::{Record, apply_returned_records};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufWriter, Read, Write};

fn parse_word(text: &str) -> Result<u64, String> {
    if text.len() != 16
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("noncanonical u64".into());
    }
    u64::from_str_radix(text, 16).map_err(|_| "invalid u64".into())
}

fn parse_samples(text: &str) -> Result<BTreeMap<u64, Vec<u64>>, String> {
    let mut map = BTreeMap::new();
    if text == "-" {
        return Ok(map);
    }
    let mut previous = None;
    for item in text.split(';') {
        let (key, values) = item.split_once(':').ok_or("sample separator")?;
        let key = parse_word(key)?;
        if previous.is_some_and(|p| key <= p) {
            return Err("sample keys are not strictly unsigned ordered".into());
        }
        previous = Some(key);
        let values = if values.is_empty() {
            Vec::new()
        } else {
            values
                .split(',')
                .map(parse_word)
                .collect::<Result<Vec<_>, _>>()?
        };
        map.insert(key, values);
    }
    Ok(map)
}

fn parse_fallbacks(text: &str) -> Result<BTreeMap<u64, u64>, String> {
    let mut map = BTreeMap::new();
    if text == "-" {
        return Ok(map);
    }
    let mut previous = None;
    for item in text.split(';') {
        let (key, value) = item.split_once(':').ok_or("fallback separator")?;
        let key = parse_word(key)?;
        if previous.is_some_and(|p| key <= p) {
            return Err("fallback keys are not strictly unsigned ordered".into());
        }
        previous = Some(key);
        map.insert(key, parse_word(value)?);
    }
    Ok(map)
}

fn parse_records(text: &str) -> Result<Vec<Record>, String> {
    if text == "-" {
        return Ok(Vec::new());
    }
    text.split(';')
        .map(|item| {
            let fields = item.split(',').collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err("record field count".into());
            }
            Ok(Record {
                key: parse_word(fields[0])?,
                tag: parse_word(fields[1])?,
                payload: parse_word(fields[2])?,
            })
        })
        .collect()
}

fn write_samples(output: &mut String, samples: &BTreeMap<u64, Vec<u64>>) {
    if samples.is_empty() {
        output.push('-');
    }
    for (index, (key, values)) in samples.iter().enumerate() {
        if index != 0 {
            output.push(';');
        }
        write!(output, "{key:016x}:").expect("String formatting");
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            write!(output, "{value:016x}").expect("String formatting");
        }
    }
}

fn write_fallbacks(output: &mut String, fallbacks: &BTreeMap<u64, u64>) {
    if fallbacks.is_empty() {
        output.push('-');
    }
    for (index, (key, value)) in fallbacks.iter().enumerate() {
        if index != 0 {
            output.push(';');
        }
        write!(output, "{key:016x}:{value:016x}").expect("String formatting");
    }
}

fn run() -> Result<(), String> {
    if std::env::args_os().len() != 1 {
        return Err("the client accepts input on stdin only".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(io::stdout().lock());
    for (index, line) in input.split_inclusive('\n').enumerate() {
        let line = line.strip_suffix('\n').ok_or("missing input LF")?;
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 || fields[0] != format!("C{index:06}") {
            return Err("input fields or ordered case ID".into());
        }
        if fields[1].len() != 2
            || !fields[1]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("noncanonical dex byte".into());
        }
        let dex_byte = u8::from_str_radix(fields[1], 16).map_err(|_| "invalid dex byte")?;
        let mut samples = parse_samples(fields[2])?;
        let mut fallbacks = parse_fallbacks(fields[3])?;
        let records = parse_records(fields[4])?;
        apply_returned_records(&mut samples, &mut fallbacks, dex_byte, &records);
        let mut output = String::from(fields[0]);
        output.push('\t');
        write_samples(&mut output, &samples);
        output.push('\t');
        write_fallbacks(&mut output, &fallbacks);
        output.push('\n');
        writer
            .write_all(output.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("invalid fixture: {error}");
        std::process::exit(2);
    }
}
