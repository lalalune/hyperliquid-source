use node94_tag_address_pair::select;
use std::io::{self, BufRead, Write};

fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "input column count");
        let number = |i: usize| u64::from_str_radix(fields[i], 16).expect("u64 hex input");
        let result = select(number(1), number(2), number(3));
        writeln!(
            out,
            "{}\tV:{:016x}:{:016x}",
            fields[0], result.rax, result.rdx
        )
        .expect("output line");
    }
}
