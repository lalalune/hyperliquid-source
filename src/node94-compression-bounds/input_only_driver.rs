extern crate node94_compression_bounds;

use node94_compression_bounds::{lz4_bound, snappy_bound};
use std::io::{self, BufRead, Write};

fn main() {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "expected id operation input_hex");
        assert!(fields[0]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_'));
        let actual = match fields[1] {
            "snappy" => snappy_bound(u64::from_str_radix(fields[2], 16).unwrap()),
            "lz4" => u64::from(lz4_bound(u32::from_str_radix(fields[2], 16).unwrap())),
            _ => panic!("unknown operation"),
        };
        writeln!(output, "{} {actual:016x}", fields[0]).unwrap();
    }
}
