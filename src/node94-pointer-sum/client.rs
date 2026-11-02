mod client_support;
use std::io::{self, BufRead, Write};
fn main() {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.expect("input I/O");
        let (id, values) = line.split_once('\t').expect("id TAB input");
        assert!(!values.contains('\t'), "client never accepts expectations");
        let words: Vec<u64> = values
            .split(',')
            .map(|v| v.parse().expect("u64 input"))
            .collect();
        assert_eq!(words.len(), 2);
        let result = client_support::evaluate(&words);
        let csv = result
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(out, "{id}\t{csv}").expect("output I/O");
    }
}
