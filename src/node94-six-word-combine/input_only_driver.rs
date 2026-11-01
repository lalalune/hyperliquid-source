//! Input-only runner for synthetic memory images, without expected values.
use node94_six_word_combine::combine;
use std::env;
use std::fs;
use std::io::{self, BufWriter, Write};

fn hex_bytes(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0, "even hex length");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex byte"))
        .collect()
}

fn main() {
    let path = env::args().nth(1).expect("one input TSV path");
    let input = fs::read_to_string(path).expect("read TSV");
    let mut output = BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 5, "five fields");
        let source: usize = fields[0].parse().expect("source offset");
        let destination: usize = fields[1].parse().expect("destination offset");
        let first = u64::from_str_radix(fields[2], 16).expect("coefficient bits") as i64;
        let second = u64::from_str_radix(fields[3], 16).expect("coefficient bits") as i64;
        let mut image = hex_bytes(fields[4]);
        match combine(&mut image, source, destination, first, second) {
            Ok(value) => {
                write!(
                    output,
                    "ok:{:016x},{:016x},{:016x},{:016x},{:016x}",
                    value.rax, value.rdx, value.rbx, value.r14, value.r15
                )
                .unwrap();
                for word in value.words {
                    write!(output, ",{word:016x}").unwrap();
                }
                write!(output, ":").unwrap();
            }
            Err(_) => write!(output, "span:").unwrap(),
        }
        for byte in image {
            write!(output, "{byte:02x}").unwrap();
        }
        writeln!(output).unwrap();
    }
}
