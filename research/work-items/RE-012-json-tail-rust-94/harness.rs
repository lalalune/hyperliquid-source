extern crate node94_json_tail;
use node94_json_tail::{finish_tail, TailResult};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        assert_eq!(words.len(), 3);
        let word = words[0].parse().unwrap();
        let cursor = words[1].parse().unwrap();
        let input: Vec<u8> = if words[2] == "-" {
            Vec::new()
        } else {
            words[2]
                .as_bytes()
                .chunks_exact(2)
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect()
        };
        match finish_tail(word, &input, cursor) {
            TailResult::DelegateError { cursor } => println!("D {cursor}"),
            TailResult::Complete { cursor } => println!("A {cursor}"),
            TailResult::Trailing { cursor, code } => println!("E {cursor} {code}"),
        }
    }
}
