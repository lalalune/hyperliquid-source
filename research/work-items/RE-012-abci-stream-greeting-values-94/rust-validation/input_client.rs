//! Input-only fixed transport from the frozen PROTOCOL.md. No fixture access.
#![forbid(unsafe_code)]

use node94_abci_greeting_values::{
    Error, Greeting, NativeError, Reader, SignatureMap, decode_with_limit,
};
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};

type Transport<T> = Result<T, &'static str>;

struct Frame<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Frame<'a> {
    fn take(&mut self, count: usize) -> Transport<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or("input length overflow")?;
        let value = self.bytes.get(self.at..end).ok_or("short input frame")?;
        self.at = end;
        Ok(value)
    }

    fn byte(&mut self) -> Transport<u8> {
        Ok(self.take(1)?[0])
    }

    fn word(&mut self) -> Transport<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "u64 width")?,
        ))
    }

    fn count(&mut self) -> Transport<usize> {
        let value = u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| "u32 width")?);
        usize::try_from(value).map_err(|_| "host count range")
    }
}

fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn count(out: &mut Vec<u8>, value: usize) -> Transport<()> {
    out.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| "output count range")?
            .to_le_bytes(),
    );
    Ok(())
}

fn mapping(out: &mut Vec<u8>, value: &SignatureMap) -> Transport<()> {
    count(out, value.len())?;
    for (key, signature) in value {
        out.extend_from_slice(key);
        for limb in signature.limbs {
            word(out, limb);
        }
        out.push(signature.recovery);
    }
    Ok(())
}

fn error(out: &mut Vec<u8>, value: &Error) -> Transport<()> {
    let Error::Native(value) = value else {
        return Err("source policy refusal outside native qualification domain");
    };
    out.push(8);
    match value {
        NativeError::UnexpectedEnd { needed } => {
            out.push(0);
            word(out, *needed);
        }
        NativeError::BulkUnexpectedEnd => out.push(1),
        NativeError::LimitExceeded => out.push(2),
        NativeError::InvalidIntegerType { expected, found } => {
            out.extend_from_slice(&[3, *expected, *found]);
        }
        NativeError::UnexpectedVariant {
            type_name,
            minimum,
            maximum,
            found,
        } => {
            out.push(5);
            out.push(u8::try_from(type_name.len()).map_err(|_| "type name length")?);
            out.extend_from_slice(type_name.as_bytes());
            for value in [minimum, maximum, found] {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    Ok(())
}

fn value(out: &mut Vec<u8>, greeting: &Greeting) -> Transport<()> {
    match greeting {
        Greeting::Data0 {
            bytes,
            scalar,
            hash,
            signatures,
        } => {
            out.push(0);
            count(out, bytes.len())?;
            out.extend_from_slice(bytes);
            word(out, *scalar);
            out.extend_from_slice(hash);
            mapping(out, signatures)?;
        }
        Greeting::Data1 {
            bytes,
            scalar,
            hash,
            first,
            second,
        } => {
            out.push(1);
            count(out, bytes.len())?;
            out.extend_from_slice(bytes);
            word(out, *scalar);
            out.extend_from_slice(hash);
            mapping(out, first)?;
            mapping(out, second)?;
        }
        Greeting::Data2 {
            bytes,
            scalar,
            records,
        } => {
            out.push(2);
            count(out, bytes.len())?;
            out.extend_from_slice(bytes);
            word(out, *scalar);
            for record in records.iter() {
                word(out, record.first);
                word(out, record.second);
                out.extend_from_slice(&record.bytes);
            }
        }
        Greeting::Triple(values) => {
            out.push(3);
            for value in values {
                word(out, *value);
            }
        }
        Greeting::Empty2 => out.push(4),
        Greeting::Empty3 => out.push(5),
        Greeting::Empty4 => out.push(6),
        Greeting::Empty5 => out.push(7),
    }
    Ok(())
}

fn evaluate(raw: &[u8]) -> Transport<Vec<u8>> {
    let mut frame = Frame { bytes: raw, at: 0 };
    if frame.take(4)? != b"G94R" {
        return Err("input magic");
    }
    let operation = frame.byte()?;
    let mut out = Vec::new();
    match operation {
        0 => {
            let enabled = frame.byte()?;
            if enabled > 1 {
                return Err("enabled tag");
            }
            let limit = frame.word()?;
            let charged = frame.word()?;
            let cursor = usize::try_from(frame.word()?).map_err(|_| "cursor host range")?;
            let size = frame.count()?;
            let data = frame.take(size)?;
            if frame.at != raw.len() {
                return Err("trailing frame bytes");
            }
            let mut reader = Reader::new(
                data,
                cursor,
                if enabled == 1 { Some(limit) } else { None },
                charged,
            )
            .map_err(|_| "Reader state policy refusal")?;
            let result = reader.decode();
            word(
                &mut out,
                u64::try_from(reader.cursor()).map_err(|_| "cursor output range")?,
            );
            word(
                &mut out,
                u64::try_from(reader.remaining()).map_err(|_| "remaining output range")?,
            );
            word(&mut out, reader.charged());
            match result {
                Ok(greeting) => value(&mut out, &greeting)?,
                Err(failure) => error(&mut out, &failure)?,
            }
        }
        1 => {
            let limit = frame.word()?;
            let size = frame.count()?;
            let data = frame.take(size)?;
            if frame.at != raw.len() {
                return Err("trailing frame bytes");
            }
            match decode_with_limit(data, limit) {
                Ok(decoded) => {
                    value(&mut out, &decoded.greeting)?;
                    out.push(1);
                    word(
                        &mut out,
                        u64::try_from(decoded.consumed).map_err(|_| "consumed output range")?,
                    );
                }
                Err(failure) => {
                    error(&mut out, &failure)?;
                    out.push(0);
                }
            }
        }
        _ => return Err("operation tag"),
    }
    Ok(out)
}

fn decode_hex(text: &str) -> Transport<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err("odd hex length");
    }
    fn digit(byte: u8) -> Transport<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("non-lowercase hex"),
        }
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn run() -> Transport<()> {
    if std::env::args_os().len() != 1 {
        return Err("unexpected arguments");
    }
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = Vec::new();
    let mut identifiers = BTreeSet::new();
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line).map_err(|_| "input read")? == 0 {
            break;
        }
        let text = line.strip_suffix('\n').ok_or("missing line terminator")?;
        let (id, raw) = text.split_once('\t').ok_or("line fields")?;
        if id.len() != 7
            || !id.starts_with('C')
            || !id.as_bytes()[1..].iter().all(u8::is_ascii_digit)
        {
            return Err("opaque identifier");
        }
        if !identifiers.insert(id.to_owned()) {
            return Err("duplicate identifier");
        }
        let result = evaluate(&decode_hex(raw)?)?;
        writeln!(output, "{id}\t{}", encode_hex(&result)).map_err(|_| "output write")?;
    }
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&output).map_err(|_| "output write")?;
    stdout.flush().map_err(|_| "output flush")
}

fn main() {
    if let Err(message) = run() {
        eprintln!("transport: {message}");
        std::process::exit(2);
    }
}
