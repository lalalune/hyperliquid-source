//! Input-only client; expected triples and comparison stay outside this process.
use node94_bounded_key_walk::{raw_triple, Node, Refusal};
use std::io::{BufRead, Write};

fn word(text: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(text, 16)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::open(std::env::args().nth(1).ok_or("input path required")?)?;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err("expected start, index, key and nodes".into());
        }
        let mut nodes = Vec::new();
        if fields[3] != "-" {
            for record in fields[3].split(',') {
                let parts: Vec<_> = record.split(':').collect();
                if parts.len() != 4 {
                    return Err("expected four node fields".into());
                }
                nodes.push(Node {
                    id: word(parts[0])?,
                    next: word(parts[1])?,
                    word_e4: u16::from_str_radix(parts[2], 16)?,
                    word_e6: u16::from_str_radix(parts[3], 16)?,
                });
            }
        }
        match raw_triple(&nodes, word(fields[0])?, word(fields[1])?, word(fields[2])?) {
            Ok([a, b, c]) => writeln!(output, "ok:{a:016x},{b:016x},{c:016x}")?,
            Err(Refusal::InvalidNodeMap) => writeln!(output, "map")?,
            Err(Refusal::MissingNode(id)) => writeln!(output, "missing:{id:016x}")?,
            Err(Refusal::NonterminatingCycle) => writeln!(output, "cycle")?,
        }
    }
    output.flush()?;
    Ok(())
}
