#[path = "support/row_codec.rs"]
mod row_codec;
use std::io::{self, BufRead, Write};
fn main() -> io::Result<()> {
    if std::env::args().len() != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "stdin TSV only"));
    }
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for (index, line) in stdin.lock().lines().enumerate() {
        let value = row_codec::row(&line?).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("row{}: {e}", index + 1)))?;
        writeln!(&mut output, "{value}")?;
    }
    output.flush()
}
