use node115_u64_key_hash::fresh_hash;
use std::io::{self, Read, Write};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for row in input.lines() {
        let v: Vec<u64> = row.split('\t').map(|x| x.parse().unwrap()).collect();
        assert_eq!(v.len(), 3);
        writeln!(out, "{}", fresh_hash(v[0], v[1], v[2])).unwrap();
    }
}
