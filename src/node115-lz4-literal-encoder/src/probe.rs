use node115_lz4_literal_encoder::{Error, encode};
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<usize> = line
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();
        assert_eq!(v.len(), 6);
        let input: Vec<u8> = (0..v[0])
            .map(|i| (i.wrapping_mul(37).wrapping_add(v[5])) as u8)
            .collect();
        let mut sink = vec![165; v[3]];
        let mut used = v[4];
        let label = match encode(&input, v[1], v[2], &mut sink, &mut used) {
            Ok(()) => "ok",
            Err(Error::Domain) => "domain",
            Err(Error::Anchor) => "anchor",
            Err(Error::Token) => "token",
            Err(Error::Extension) => "extension",
            Err(Error::Literals) => "literals",
        };
        write!(out, "{label} {used} ").unwrap();
        for byte in sink {
            write!(out, "{byte:02x}").unwrap();
        }
        writeln!(out).unwrap();
    }
}
