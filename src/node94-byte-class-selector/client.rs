use node94_byte_class_selector::select;
use std::io::{self, Read, Write};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3);
        let first = u32::from_str_radix(fields[1], 16).expect("first u32");
        let second = u32::from_str_radix(fields[2], 16).expect("second u32");
        writeln!(out, "{}\t{:016x}", fields[0], select(first, second)).unwrap();
    }
}
