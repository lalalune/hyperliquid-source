//! Synthetic raw-input runner. No expectations or target instruction bytes.
use node94_thirty_step_matrix::reduce;
use std::env;
use std::fs;
use std::io::{self, BufWriter, Write};

fn main() {
    let path = env::args().nth(1).expect("input TSV path");
    let input = fs::read_to_string(path).expect("read TSV");
    let mut output = BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "three input words");
        let mut input_words = [0_u64; 3];
        for (word, field) in input_words.iter_mut().zip(fields) {
            *word = u64::from_str_radix(field, 16).expect("u64 hexadecimal word");
        }
        let r = reduce(input_words[0], input_words[1], input_words[2]);
        let words = [
            r.rax, r.rbx, r.rcx, r.rdx, r.rbp, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13,
            r.r14, r.r15,
        ];
        for (index, word) in words.iter().enumerate() {
            if index != 0 {
                write!(output, ",").unwrap();
            }
            write!(output, "{word:016x}").unwrap();
        }
        writeln!(output).unwrap();
    }
}
