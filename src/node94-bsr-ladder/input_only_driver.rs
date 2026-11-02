#![forbid(unsafe_code)]
use node94_bsr_ladder::ladder;
use std::io::{self, BufRead, Write};

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 2, "one input-only TSV path is required");
    let file = std::fs::File::open(&arguments[1]).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::BufReader::new(file).lines() {
        let line = line.unwrap();
        let values: Vec<u32> = line.split('\t').map(|x| x.parse().unwrap()).collect();
        assert_eq!(values.len(), 4, "four unsigned 32-bit inputs are required");
        match ladder(values[0], values[1], values[2], values[3]) {
            Some(value) => writeln!(output, "{value}"),
            None => writeln!(output, "none"),
        }
        .unwrap();
    }
}
