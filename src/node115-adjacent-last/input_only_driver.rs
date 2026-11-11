//! Owned synthetic adapter; no original protocol, record type or ABI claim.
use node115_adjacent_last::{compact, Record};
use std::io::{self, BufRead, Write};

fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        assert_eq!(line.len() % 64, 0);
        let data: Vec<u8> = (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect();
        let mut rows: Vec<Record> = data
            .chunks_exact(32)
            .map(|s| s.try_into().unwrap())
            .collect();
        let len = compact(&mut rows);
        write!(out, "[{len},\"").unwrap();
        // Include every old-length byte, rather than just the visible prefix.
        for row in rows {
            for byte in row {
                write!(out, "{byte:02x}").unwrap();
            }
        }
        writeln!(out, "\"]").unwrap();
    }
}
