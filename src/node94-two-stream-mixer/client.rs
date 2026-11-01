//! Separately linked client. Stdin contains inputs only, never expectations.
use node94_two_stream_mixer::two_stream_mix;
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for row in text.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 5);
        let seed_b = u64::from_str_radix(fields[1], 16).unwrap();
        let seed_a = u64::from_str_radix(fields[2], 16).unwrap();
        let key = u64::from_str_radix(fields[3], 16).unwrap();
        let data: Vec<_> = if fields[4] == "-" {
            Vec::new()
        } else {
            assert_eq!(fields[4].len() % 2, 0);
            (0..fields[4].len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&fields[4][i..i + 2], 16).unwrap())
                .collect()
        };
        println!(
            "{}\t{:016x}",
            fields[0],
            two_stream_mix(&data, seed_b, seed_a, key)
        );
    }
}
