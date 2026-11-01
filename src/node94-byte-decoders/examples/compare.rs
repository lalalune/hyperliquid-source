//! Input-only TSV client for the independent pre-source mathematical authority.

use hyperliquid_node94_byte_decoders::{Budget, DecodeError, read_bool, read_u8};
use std::io::{self, BufRead, Write};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn decimal(text: &str) -> io::Result<u64> {
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("expected a canonical decimal u64"));
    }
    text.parse().map_err(|_| invalid("decimal exceeds u64"))
}

fn hex(text: &str) -> io::Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(invalid("odd hex length"));
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
                _ => Err(invalid("expected lowercase hex")),
            }
        })
        .collect()
}

fn optional_number(output: &mut impl Write, number: Option<u64>) -> io::Result<()> {
    match number {
        Some(value) => write!(output, "{value}"),
        None => write!(output, "null"),
    }
}

fn row(line: &str, output: &mut impl Write) -> io::Result<()> {
    let fields: Vec<_> = line.split('\t').collect();
    if fields.len() != 6 {
        return Err(invalid("expected id,kind,mode,counter,limit,hex"));
    }
    let id = fields[0];
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(invalid("invalid row id"));
    }
    let mode = u32::try_from(decimal(fields[2])?).map_err(|_| invalid("mode exceeds u32"))?;
    let counter = decimal(fields[3])?;
    let mut budget = Budget { mode_word: mode, counter, limit: decimal(fields[4])? };
    let bytes = hex(fields[5])?;
    let mut input = bytes.as_slice();
    let result = match fields[1] {
        "u8" => read_u8(&mut input, &mut budget),
        "bool" => read_bool(&mut input, &mut budget).map(u8::from),
        _ => return Err(invalid("unsupported decoder kind")),
    };
    let (tag, byte, word8) = match result {
        Ok(value) => (18, Some(u64::from(value)), None),
        Err(DecodeError::UnexpectedEnd { needed }) => (0, None, Some(needed)),
        Err(DecodeError::BudgetExceeded { word8_write }) => (2, None, word8_write),
        Err(DecodeError::InvalidBooleanByte { found }) => (8, Some(u64::from(found)), None),
    };
    write!(output, "{{\"byte1_written\":")?;
    optional_number(output, byte)?;
    write!(output, ",\"consumed\":{},\"counter_after\":{},\"counter_written\":{},\"id\":\"{}\",\"remaining\":{},\"tag\":{},\"tail_hex\":\"",
        bytes.len() - input.len(), budget.counter, budget.counter != counter, id, input.len(), tag)?;
    for byte in input {
        write!(output, "{byte:02x}")?;
    }
    write!(output, "\",\"word8_written\":")?;
    optional_number(output, word8)?;
    writeln!(output, "}}")
}

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for (index, line) in stdin.lock().lines().enumerate() {
        row(&line?, &mut output)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("row {}: {error}", index + 1)))?;
    }
    output.flush()
}
