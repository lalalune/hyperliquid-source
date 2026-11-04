use node115_packed_millis::convert;
use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let f: Vec<u32> = line.split('\t').map(|s| s.parse().unwrap()).collect();
        assert_eq!(f.len(), 4);
        assert!(f[0] < 5);
        let result = convert(f[1], f[2], f[3]);
        writeln!(out, "{}\t{}", result.raw, result.clamped).unwrap();
    }
}
