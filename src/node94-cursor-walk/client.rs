//! Input-only client: stdin contains indices and raw records, never expectations.
use node94_cursor_walk::{RECORD_BYTES, walk};
use std::io::{self, BufRead, BufWriter, Write};

fn main() {
    let mut output = BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4);
        let mut cursor = usize::from_str_radix(fields[1], 16).expect("cursor");
        let limit = usize::from_str_radix(fields[2], 16).expect("limit");
        let mut raw = Vec::new();
        if fields[3] != "-" {
            assert_eq!(fields[3].len() % 2, 0);
            for index in (0..fields[3].len()).step_by(2) {
                raw.push(u8::from_str_radix(&fields[3][index..index + 2], 16).expect("byte"));
            }
        }
        assert_eq!(raw.len() % RECORD_BYTES, 0);
        let records: Vec<[u8; RECORD_BYTES]> = raw
            .chunks_exact(RECORD_BYTES)
            .map(|row| row.try_into().unwrap())
            .collect();
        let status = match walk(&records, &mut cursor, limit) {
            Ok(true) => 'T',
            Ok(false) => 'F',
            Err(_) => 'E',
        };
        writeln!(output, "{}\t{}\t{:016x}", fields[0], status, cursor).expect("output");
    }
}
