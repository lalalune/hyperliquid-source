use node94_square384::{Square, apply, square};
use std::io::{self, BufRead};
fn number(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}
fn words(s: &str) -> [u64; 6] {
    assert_eq!(s.len(), 96);
    let mut value = [0; 6];
    for i in 0..6 {
        value[i] = number(&s[80 - i * 16..96 - i * 16]);
    }
    value
}
fn bytes(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn output(id: &str, result: Option<Square>, image: Option<&[u8]>) {
    let value = match result {
        None => "E".to_owned(),
        Some(s) => {
            let r = s.registers;
            let mut value = "V".to_owned();
            for x in [
                r.rax, r.rbx, r.rcx, r.rdx, r.rbp, r.rsi, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13,
                r.r14, r.r15,
            ]
            .into_iter()
            .chain(s.words)
            {
                value.push_str(&format!(":{x:016x}"));
            }
            value
        }
    };
    let raw = image
        .filter(|v| !v.is_empty())
        .map(|v| v.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .unwrap_or_else(|| "-".to_owned());
    println!("{id}\t{value}\t{raw}");
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 7);
        match f[1] {
            "V" => output(f[0], Some(square(words(f[2]))), None),
            "I" => {
                let mut image = bytes(f[5]);
                let result = apply(&mut image, number(f[2]), number(f[3]), number(f[4]));
                output(f[0], result, Some(&image));
            }
            _ => panic!("unknown input mode"),
        }
    }
}
