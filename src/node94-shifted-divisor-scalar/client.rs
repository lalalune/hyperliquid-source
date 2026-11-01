//! Separately linked client: stdin contains inputs only, never expectations.
use node94_shifted_divisor_scalar::shifted_divisor_scalar;
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        let numerator = u128::from_str_radix(fields[1], 16).unwrap();
        let threshold = u128::from_str_radix(fields[2], 16).unwrap();
        println!(
            "{}\t{:016x}",
            fields[0],
            shifted_divisor_scalar(numerator, threshold)
        );
    }
}
