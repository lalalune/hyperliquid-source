//! Input-only driver: no expected-output file interface.
use node94_bounded_byte_selector::{matches_stored, select_byte};
use std::fmt::Write as _;
use std::io::{self, Read};
fn word(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap()
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = String::new();
    for line in input.lines() {
        let c: Vec<_> = line.split('\t').collect();
        assert_eq!(c.len(), 9);
        let text = c[8];
        let image: Vec<u8> = if text == "-" {
            Vec::new()
        } else {
            assert_eq!(text.len() % 2, 0);
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect()
        };
        let answer = match c[1] {
            "H" => select_byte(
                &image,
                word(c[2]),
                word(c[3]),
                word(c[4]),
                u32::try_from(word(c[5])).unwrap(),
                u32::try_from(word(c[6])).unwrap(),
                c[7].parse().unwrap(),
            )
            .map(u64::from),
            "W" => matches_stored(&image, word(c[2]), word(c[3])).map(u64::from),
            _ => panic!("unknown operation"),
        };
        let result = match answer {
            Ok(value) => format!("V:{value:016x}"),
            Err(_) => "E".to_owned(),
        };
        writeln!(&mut output, "{}\t{}", c[0], result).unwrap();
    }
    print!("{output}");
}
