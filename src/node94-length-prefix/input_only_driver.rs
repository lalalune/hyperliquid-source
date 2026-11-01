//! Input-only client. Expected results and comparisons remain outside this process.
use node94_length_prefix::{encode, Payload, Refusal};
use std::fmt::Write as _;
use std::io::{BufRead, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::fs::File::open(std::env::args().nth(1).ok_or("input path required")?)?;
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in std::io::BufReader::new(input).lines() {
        let line = line?;
        let columns: Vec<_> = line.split('\t').collect();
        if columns.len() != 3 { return Err("expected three input columns".into()); }
        let length = u64::from_str_radix(columns[0], 16)?;
        let raw = if columns[1] == "-" { "" } else { columns[1] };
        if raw.len() % 2 != 0 || !raw.is_ascii() { return Err("invalid byte hex".into()); }
        let mut memory = (0..raw.len()).step_by(2)
            .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        let (kind, value) = columns[2].split_once(':').ok_or("payload syntax")?;
        let payload = match kind {
            "e" => Payload::External(u8::from_str_radix(value, 16)?),
            "o" => Payload::Output(usize::from_str_radix(value, 16)?),
            _ => return Err("unknown payload mode".into()),
        };
        let status = match encode(&mut memory, length, payload) {
            Ok(size) => format!("ok:{size}"),
            Err(Refusal::OutputTooShort) => "short".into(),
            Err(Refusal::PayloadOutsideOutput) => "index".into(),
        };
        let mut hex = String::new();
        for byte in memory { write!(hex, "{byte:02x}")?; }
        writeln!(out, "{status}:{hex}")?;
    }
    out.flush()?;
    Ok(())
}
