use node115_wrapped_u64_search::probe;
use std::io::{self, BufRead, Write};
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (header, keys) = line.split_once('\t').unwrap();
        let header: Vec<u64> = header.split(',').map(|s| s.parse().unwrap()).collect();
        assert_eq!(header.len(), 4);
        assert!(header[0] < 2);
        let keys: Vec<u64> = if keys == "-" {
            Vec::new()
        } else {
            keys.split(',').map(|s| s.parse().unwrap()).collect()
        };
        let found = probe(
            &keys,
            header[1].try_into().unwrap(),
            header[2].try_into().unwrap(),
            header[3],
        )
        .expect("qualified geometry");
        writeln!(out, "[{},{}]", found.status, found.index).unwrap();
    }
}
