mod protocol;
use std::io::{self, Write};

fn main() {
    let input = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        writeln!(output, "{}", protocol::run(line)).unwrap();
    }
}
