//! Input-only client: no expectations, corpus, oracle or filesystem reads.
use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read, Write};
use visor_duration_value::convert_bits;

fn hex_word(text: &str) -> Result<u64, String> {
    if text.len() != 16
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected sixteen lowercase hex digits".into());
    }
    u64::from_str_radix(text, 16).map_err(|_| "hex word range".into())
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
        let (id, raw) = line.split_once('\t').ok_or("missing tab")?;
        hex_word(id)?;
        if !ids.insert(id) {
            return Err("duplicate opaque ID".into());
        }
        let value = convert_bits(hex_word(raw)?);
        writeln!(output, "{id}\t{}\t{}", value.seconds(), value.nanoseconds()).unwrap();
    }
    // Publish nothing until every input record has passed framing admission.
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
