use node94_unsigned_clamp::clamp;
use std::io::{self, Read, Write};

fn field(text: &str) -> Option<u64> {
    if text == "-" {
        None
    } else {
        Some(u64::from_str_radix(text, 16).expect("hex field"))
    }
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let parts: Vec<_> = line.split('\t').collect();
        assert_eq!(parts.len(), 5);
        let result = clamp(
            field(parts[1]).expect("mandatory tag"),
            field(parts[2]),
            field(parts[3]),
            field(parts[4]),
        );
        match result {
            Ok(registers) => writeln!(
                output,
                "{}\tV:{:016x}:{:016x}",
                parts[0], registers.rax, registers.rcx
            ),
            Err(_) => writeln!(output, "{}\tE", parts[0]),
        }
        .unwrap();
    }
}
