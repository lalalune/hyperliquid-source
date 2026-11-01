// Input-only client. Expected results are never available to this program.
use node94_halving384_family::{Wrapper, apply, step};
use std::io::{self, BufRead, Write};
fn num(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}
fn integer(s: &str) -> [u64; 6] {
    assert_eq!(s.len(), 96);
    core::array::from_fn(|i| num(&s[80 - 16 * i..96 - 16 * i]))
}
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 8);
        let (registers, image): (Option<Vec<u64>>, String) = if f[1] == "C" {
            let r = step(integer(f[2]), integer(f[3]));
            let mut values = vec![r.rax, r.rsi, r.rbx, r.rbp, r.r14, r.r15];
            values.extend(r.words);
            (Some(values), "-".to_string())
        } else {
            let raw = if f[7] == "-" { "" } else { f[7] };
            let mut image: Vec<u8> = (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
                .collect();
            let mode = match f[1] {
                "S" => Wrapper::Single,
                "R" => Wrapper::Repeated {
                    raw_count: num(f[6]),
                },
                _ => panic!("mode"),
            };
            let r = apply(&mut image, num(f[2]), num(f[3]), num(f[4]), num(f[5]), mode);
            let values =
                r.map(|r| vec![r.rax, r.rdx, r.rsi, r.rcx, r.rdi, r.r8, r.r9, r.r10, r.r11]);
            let encoded = if image.is_empty() {
                "-".into()
            } else {
                image.iter().map(|x| format!("{x:02x}")).collect()
            };
            (values, encoded)
        };
        write!(out, "{}\t", f[0]).unwrap();
        if let Some(values) = registers {
            write!(out, "V").unwrap();
            for v in values {
                write!(out, ":{v:016x}").unwrap();
            }
        } else {
            write!(out, "E").unwrap();
        }
        writeln!(out, "\t{image}").unwrap();
    }
}
