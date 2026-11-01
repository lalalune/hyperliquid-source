// Input-only native client: no expected-output path or expected values.
use node94_u256_bound_check::{compare_bound, compare_nonzero};
use std::io::{self, BufRead, Write};
fn words(text: &str) -> [u64; 4] {
    let values: Vec<_> = text
        .split(':')
        .map(|s| u64::from_str_radix(s, 16).unwrap())
        .collect();
    values.try_into().unwrap()
}
fn main() {
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4);
        let left = words(fields[2]);
        let r = match fields[1] {
            "G" => compare_nonzero(left, words(fields[3])),
            "W" => {
                assert_eq!(fields[3], "-");
                compare_bound(left)
            }
            _ => panic!("unknown input mode"),
        };
        writeln!(
            output,
            "{}\tV:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}",
            fields[0], r.rax, r.rdx, r.rsi, r.r8, r.r9, r.r10, r.r11
        )
        .unwrap();
    }
}
