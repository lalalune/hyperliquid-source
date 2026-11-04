use node115_lz4_match_extension::{Boundary, extend};
use std::io::{self, BufRead};
fn bytes(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let v: Vec<_> = line.split('\t').collect();
        let left = bytes(v[0]);
        let right = bytes(v[1]);
        let mut cursor: usize = v[2].parse().unwrap();
        let other: usize = v[3].parse().unwrap();
        let old = cursor;
        let result = if left == right {
            extend(&left, &left, &mut cursor, other)
        } else {
            extend(&left, &right, &mut cursor, other)
        };
        match result {
            Ok(n) => println!("ok:{n}:{cursor}"),
            Err(e) => {
                assert_eq!(cursor, old);
                let label = match e {
                    Boundary::SourceShorterThanSix => "adapter",
                    Boundary::LeftCursor => "left-boundary",
                    Boundary::RightCursor => "right-boundary",
                };
                println!("{label}:{cursor}");
            }
        }
    }
}
