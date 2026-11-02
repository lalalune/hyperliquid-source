//! Synthetic-input runner; contains no expected values or target instructions.
use node94_packed_date_add::add_days;
use std::env;
use std::fs;
use std::io::{self, BufWriter, Write};

fn main() {
    let path = env::args().nth(1).expect("one input TSV path");
    let inputs = fs::read_to_string(path).expect("read input TSV");
    let mut output = BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        let (raw, delta) = line.split_once('\t').expect("two fields");
        let packed = u32::from_str_radix(raw, 16).expect("u32 bits");
        let delta: i32 = delta.parse().expect("i32 delta");
        match add_days(packed, delta) {
            Ok(value) => writeln!(output, "ok:{value:08x}").unwrap(),
            Err(_) => writeln!(output, "invalid").unwrap(),
        }
    }
}
