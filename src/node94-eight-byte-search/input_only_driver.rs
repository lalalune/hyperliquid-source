//! Input-only protocol client; comparisons and expected values stay external.
use node94_eight_byte_search::raw_index;
use std::io::{BufRead, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(std::env::args().nth(1).ok_or("input path required")?)?;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        let columns: Vec<_> = line.split('\t').collect();
        if columns.len() != 3 {
            return Err("expected key, limit, and entries".into());
        }
        let key = u64::from_str_radix(columns[0], 16)?;
        let limit = u64::from_str_radix(columns[1], 16)?;
        let entries = if columns[2] == "-" {
            Vec::new()
        } else {
            columns[2]
                .split(',')
                .map(|part| u64::from_str_radix(part, 16))
                .collect::<Result<Vec<_>, _>>()?
        };
        writeln!(output, "{}", raw_index(&entries, key, limit))?;
    }
    output.flush()?;
    Ok(())
}
