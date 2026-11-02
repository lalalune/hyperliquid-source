//! Input-only qualification of the existing real MIT provider.
use node94_action_signable::keccak256;
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};

fn nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("expected lowercase hexadecimal".into()),
    }
}

fn run() -> Result<(), String> {
    if std::env::args().len() != 1 {
        return Err("client accepts no arguments".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())?;
    let mut ids = HashSet::new();
    let mut output = String::new();
    for line in input.split_inclusive('\n') {
        let line = line.strip_suffix('\n').ok_or("missing LF")?;
        let (id, encoded) = line.split_once('\t').ok_or("missing tab")?;
        if id.len() != 24 || !id.bytes().all(|b| nibble(b).is_ok()) {
            return Err("expected opaque 24-digit lowercase hex ID".into());
        }
        if !ids.insert(id) {
            return Err("duplicate ID".into());
        }
        let message = if encoded == "-" {
            Vec::new()
        } else {
            if encoded.is_empty() || !encoded.len().is_multiple_of(2) {
                return Err("expected even nonempty hex or empty marker".into());
            }
            let mut bytes = Vec::with_capacity(encoded.len() / 2);
            for pair in encoded.as_bytes().chunks_exact(2) {
                bytes.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
            }
            bytes
        };
        let digest = keccak256(&message);
        write!(output, "{id}\t").map_err(|e| e.to_string())?;
        for byte in digest.as_bytes() {
            write!(output, "{byte:02x}").map_err(|e| e.to_string())?;
        }
        output.push('\n');
    }
    // Parsing and evaluation finish before publishing any successful prefix.
    io::stdout()
        .write_all(output.as_bytes())
        .map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("invalid input: {error}");
        std::process::exit(2);
    }
}
