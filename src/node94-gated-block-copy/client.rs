//! Input-only native evidence client; has no expected-output file interface.
use node94_gated_block_copy::copy_block;
use std::fmt::Write as _;
use std::io::{self, Read};
fn offset(s: &str) -> usize {
    usize::from_str_radix(s, 16).unwrap()
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut output = String::new();
    for line in input.lines() {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 7);
        let encoded = columns[6];
        let mut image: Vec<u8> = if encoded == "-" {
            Vec::new()
        } else {
            assert_eq!(encoded.len() % 2, 0);
            (0..encoded.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap())
                .collect()
        };
        let before = image.clone();
        let result = copy_block(
            &mut image,
            offset(columns[1]),
            offset(columns[2]),
            offset(columns[3]),
            columns[4].parse().unwrap(),
            columns[5].parse().unwrap(),
        );
        let status = match result {
            Ok(value) => format!("V:{value:016x}"),
            Err(_) => "E".to_owned(),
        };
        let mut difference = String::new();
        for (i, (&old, &new)) in before.iter().zip(image.iter()).enumerate() {
            if old != new {
                if !difference.is_empty() {
                    difference.push(',');
                }
                write!(&mut difference, "{i:x}:{new:02x}").unwrap();
            }
        }
        if difference.is_empty() {
            difference.push('-');
        }
        writeln!(&mut output, "{}\t{}\t{}", columns[0], status, difference).unwrap();
    }
    print!("{output}");
}
