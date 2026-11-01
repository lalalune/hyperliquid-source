// Input-only qualification client; no expected-output path or values.
use node94_correction384_family::{
    Core, Input, Registers, apply_core, apply_pair, apply_single, combine,
};
use std::io::{self, BufRead, Write};
fn n(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}
fn integer(s: &str) -> [u64; 6] {
    assert_eq!(s.len(), 96);
    core::array::from_fn(|i| n(&s[80 - 16 * i..96 - 16 * i]))
}
fn core_values(c: Core) -> Vec<u64> {
    let mut v = vec![c.rax, c.rdx, c.rsi, c.rbx, c.rbp, c.r14, c.r15];
    v.extend(c.words);
    v
}
fn wrapper_values(r: Registers) -> Vec<u64> {
    vec![r.rax, r.rdx, r.rsi, r.rcx, r.rdi, r.r8, r.r9, r.r10, r.r11]
}
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 9);
        let (values, image): (Option<Vec<u64>>, String) = if f[1] == "C" {
            (
                Some(core_values(combine(
                    integer(f[2]),
                    integer(f[3]),
                    integer(f[4]),
                ))),
                "-".into(),
            )
        } else {
            let raw = if f[8] == "-" { "" } else { f[8] };
            let mut image: Vec<u8> = (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
                .collect();
            let base = n(f[2]);
            let dest = n(f[3]);
            let right = n(f[5]);
            let corr = n(f[6]);
            let result = match f[1] {
                "F" => apply_core(&mut image, base, dest, Input::Memory(n(f[4])), right, corr)
                    .map(core_values),
                "A" => apply_core(
                    &mut image,
                    base,
                    dest,
                    Input::Registers(integer(f[7])),
                    right,
                    corr,
                )
                .map(core_values),
                "S" => {
                    apply_single(&mut image, base, dest, n(f[4]), right, corr).map(wrapper_values)
                }
                "P" => apply_pair(&mut image, base, dest, n(f[4]), right, corr).map(wrapper_values),
                _ => panic!("mode"),
            };
            let encoded = if image.is_empty() {
                "-".into()
            } else {
                image.iter().map(|x| format!("{x:02x}")).collect()
            };
            (result, encoded)
        };
        write!(out, "{}\t", f[0]).unwrap();
        if let Some(values) = values {
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
