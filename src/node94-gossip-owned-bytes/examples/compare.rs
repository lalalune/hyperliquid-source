#[path = "support/row_codec.rs"]
mod row_codec;

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    let _program = args.next();
    let mode = args.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "validator or wire mode required"))?;
    if args.next().is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "one mode argument only"));
    }
    let row = match mode.as_str() {
        "validator" => row_codec::validator_row,
        "wire" => row_codec::wire_row,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown mode")),
    };
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for (index, line) in stdin.lock().lines().enumerate() {
        let output = row(&line?).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("row{}: {error}", index + 1)))?;
        writeln!(&mut stdout, "{output}")?;
    }
    stdout.flush()
}
