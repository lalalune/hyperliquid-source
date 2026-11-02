use projection::{codec, loader_value, page_count, Codec};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut p = line.split_whitespace();
        let hex = p.next().unwrap();
        let component: Vec<u8> = if hex == "-" {
            vec![]
        } else {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        };
        let words: Vec<u64> = p.map(|s| s.parse().unwrap()).collect();
        assert_eq!(words.len(), 4);
        let c = codec(&component);
        let value = loader_value(c, words[0] != 0, words[1], words[2], words[3]);
        println!(
            "{} {} {}",
            u8::from(c == Codec::Rmp),
            value,
            page_count(value)
        );
    }
}
