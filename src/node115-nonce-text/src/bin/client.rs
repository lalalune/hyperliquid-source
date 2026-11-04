//! Input-only transport adapter. It never reads or computes expected results.

use node115_nonce_text::{Failure, decode_nonce_text};
use std::io::{self, BufRead, Write};

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid input frame")
}

fn raw_byte(text: &str) -> io::Result<u8> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}

fn hex_digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid()),
    }
}

fn run() -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        let frame = line.strip_suffix('\n').ok_or_else(invalid)?;
        let frame = frame.strip_suffix('\r').unwrap_or(frame);
        let mut fields = frame.split('\t');
        let id = fields.next().ok_or_else(invalid)?;
        let mode = raw_byte(fields.next().ok_or_else(invalid)?)?;
        let depth = raw_byte(fields.next().ok_or_else(invalid)?)?;
        let hex = fields.next().ok_or_else(invalid)?;
        if fields.next().is_some()
            || id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        if hex != "-" {
            if hex.is_empty() || !hex.len().is_multiple_of(2) {
                return Err(invalid());
            }
            bytes
                .try_reserve_exact(hex.len() / 2)
                .map_err(|_| io::Error::other("transport allocation failed"))?;
            for pair in hex.as_bytes().chunks_exact(2) {
                bytes.push(hex_digit(pair[0])? * 16 + hex_digit(pair[1])?);
            }
        }

        match decode_nonce_text(&bytes, mode, depth) {
            Ok(parsed) => {
                write!(output, "{id}\tparsed\t{}\t", parsed.consumed)?;
                if parsed.values.is_empty() {
                    write!(output, "-")?;
                } else {
                    for (index, value) in parsed.values.iter().enumerate() {
                        if index != 0 {
                            write!(output, ",")?;
                        }
                        write!(output, "{value}")?;
                    }
                }
                writeln!(output)?;
            }
            Err(failure) => {
                let label = match failure {
                    Failure::NotAdmitted => "not-admitted",
                    Failure::DepthZero => "depth-zero",
                    Failure::DepthOne => "depth-one",
                    Failure::OrderingInvariant => "order-invariant",
                    Failure::HostCapacity => "host-capacity",
                    Failure::HostAllocation => "host-allocation",
                };
                writeln!(output, "{id}\t{label}")?;
            }
        }
    }
    output.flush()
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nonce-text-client: {error}");
            std::process::ExitCode::from(2)
        }
    }
}
