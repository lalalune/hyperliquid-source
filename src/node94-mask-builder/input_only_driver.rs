use node94_mask_builder::apply;
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
        if words.len() != 4 {
            eprintln!("expected four input words");
            std::process::exit(2);
        }
        let mut slot = words[3].to_le_bytes();
        let got = apply(words[0], words[1], words[2], &mut slot);
        writeln!(
            output,
            "{:016x},{:016x},{:016x},{:016x}",
            got.rax,
            got.rcx,
            got.store_address,
            u64::from_le_bytes(slot)
        )
        .unwrap();
    }
    print!("{output}");
}
