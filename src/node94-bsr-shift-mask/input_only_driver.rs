#![forbid(unsafe_code)]
use node94_bsr_shift_mask::raw_value;
use std::io::{self, BufRead, Write};

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 2, "one input-only path is required");
    let file = std::fs::File::open(&arguments[1]).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::BufReader::new(file).lines() {
        let n: u64 = line.unwrap().parse().unwrap();
        writeln!(output, "{}", raw_value(n)).unwrap();
    }
}
