use node94_calendar_constructor::construct;
use std::fmt::Write;

fn main() {
    let path = std::env::args().nth(1).expect("input-only fixture path");
    let input = std::fs::read_to_string(path).expect("read input fixture");
    let mut output = String::new();
    for line in input.lines() {
        let words: Vec<u64> = line
            .split('\t')
            .map(|word| u64::from_str_radix(word, 16).expect("u64 input"))
            .collect();
        if words.len() != 2 {
            eprintln!("expected two input words");
            std::process::exit(2);
        }
        let got = construct(words[0], words[1]);
        writeln!(output, "{:016x},{:016x}", got.rax, got.rcx).unwrap();
    }
    print!("{output}");
}
