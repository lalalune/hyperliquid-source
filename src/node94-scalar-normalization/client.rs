use node94_scalar_normalization::normalize;
use std::io::{self, BufRead, Write};

fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 7, "input column count");
        let number = |i: usize| u64::from_str_radix(fields[i], 16).expect("u64 input");
        let bytes = if fields[6] == "-" { "" } else { fields[6] };
        assert_eq!(bytes.len() % 2, 0);
        let mut image: Vec<u8> = (0..bytes.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).expect("byte input"))
            .collect();
        let before = image.clone();
        let status = match normalize(
            &mut image,
            number(1),
            number(2),
            number(3),
            number(4),
            number(5),
        ) {
            Ok(value) => format!("V:{:016x}:{:016x}:{:016x}", value.rax, value.rdx, value.rcx),
            Err(_) => "E".into(),
        };
        let changes: Vec<_> = image
            .iter()
            .enumerate()
            .filter(|&(i, byte)| *byte != before[i])
            .map(|(i, byte)| format!("{i:x}:{byte:02x}"))
            .collect();
        let delta = if changes.is_empty() {
            "-".into()
        } else {
            changes.join(",")
        };
        writeln!(out, "{}\t{status}\t{delta}", fields[0]).expect("output line");
    }
}
