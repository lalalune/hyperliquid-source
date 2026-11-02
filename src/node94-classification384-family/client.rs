use node94_classification384_family::{
    Observations, Words, classify, classify_pair, read_pair, read_single,
};
use std::io::{self, BufRead};
fn number(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}
fn words(s: &str) -> Words {
    assert_eq!(s.len(), 96);
    let mut value = [0; 6];
    for i in 0..6 {
        value[i] = number(&s[80 - i * 16..96 - i * 16]);
    }
    value
}
fn image(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn output(id: &str, value: Option<Observations>) {
    match value {
        None => println!("{id}\tE\t-"),
        Some(v) => println!(
            "{id}\tV:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}:{:016x}\t-",
            v.rax, v.rcx, v.rdx, v.rdi, v.r8, v.r9, v.r10, v.r11
        ),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 7);
        let value = match f[1] {
            "S" => Some(classify(words(f[2]), words(f[3]))),
            "P" => Some(classify_pair(words(f[2]), words(f[3]), words(f[4]))),
            "F" => read_single(&image(f[5]), number(f[2]), number(f[3]), number(f[4])),
            "G" => read_pair(&image(f[5]), number(f[2]), number(f[3]), number(f[4])),
            _ => panic!("unknown input mode"),
        };
        output(f[0], value);
    }
}
