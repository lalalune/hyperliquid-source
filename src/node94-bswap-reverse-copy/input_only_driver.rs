//! Input-only client; no target code or expected results are linked.
use node94_bswap_reverse_copy::copy_reverse;
use std::io::{BufRead, Write};

fn main() {
    let path = std::env::args().nth(1).expect("input file");
    let input = std::io::BufReader::new(std::fs::File::open(path).expect("input file"));
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for line in input.lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3);
        let source = u64::from_str_radix(fields[0], 16).expect("source offset");
        let destination = u64::from_str_radix(fields[1], 16).expect("destination offset");
        let mut memory = if fields[2] == "-" {
            Vec::new()
        } else {
            assert_eq!(fields[2].len() % 2, 0);
            (0..fields[2].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[2][i..i + 2], 16).expect("byte"))
                .collect()
        };
        match copy_reverse(&mut memory, source, destination) {
            Ok(value) => write!(output, "ok:{value:016x}|"),
            Err(_) => write!(output, "bounds|"),
        }
        .expect("status output");
        for byte in memory {
            write!(output, "{byte:02x}").expect("byte output");
        }
        writeln!(output).expect("newline output");
    }
}
