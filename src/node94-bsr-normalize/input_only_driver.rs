#![forbid(unsafe_code)]
use node94_bsr_normalize::{normalize, Refusal};
use std::io::{self, BufRead, Write};

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 2, "one input-only TSV path is required");
    let file = std::fs::File::open(&arguments[1]).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::BufReader::new(file).lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(
            fields.len(),
            4,
            "word snapshot plus three u32 values required"
        );
        let word = if fields[0] == "-" {
            None
        } else {
            Some(fields[0].parse().unwrap())
        };
        let value = fields[1].parse().unwrap();
        let flag = fields[2].parse().unwrap();
        let refinement = fields[3].parse().unwrap();
        match normalize(word, value, flag, refinement) {
            Ok(value) => writeln!(output, "ok\t{value}"),
            Err(Refusal::MissingWord) => writeln!(output, "missing"),
            Err(Refusal::UndefinedBitScan) => writeln!(output, "undefined"),
        }
        .unwrap();
    }
}
