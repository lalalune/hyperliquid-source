//! Input-only client: compact zero counts are actual inputs, never expectations.
use node94_decimal_u64_parser::parse;
use std::io::{BufRead, Write};

fn main() {
    let path = std::env::args().nth(1).expect("input file");
    let input = std::io::BufReader::new(std::fs::File::open(path).expect("input file"));
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for line in input.lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3);
        let zeroes = u64::from_str_radix(fields[0], 16).expect("zero count");
        let previous = u64::from_str_radix(fields[1], 16).expect("previous output");
        let tail: Vec<u8> = if fields[2] == "-" {
            Vec::new()
        } else {
            assert_eq!(fields[2].len() % 2, 0);
            (0..fields[2].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[2][i..i + 2], 16).expect("byte"))
                .collect()
        };
        match parse(zeroes, &tail, previous) {
            Ok(result) => writeln!(
                output,
                "ok:{:016x},{:016x},{:016x},{:016x},{:016x}",
                result.rax,
                result.consumed,
                result.remaining,
                result.output,
                u64::from(result.output_written)
            ),
            Err(_) => writeln!(output, "length"),
        }
        .expect("result output");
    }
}
