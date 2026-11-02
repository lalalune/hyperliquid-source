use projection::{delay, k_value};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let p: Vec<u64> = line
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(p.len(), 7);
        let k = k_value(
            if p[2] != 0 { Some(p[3]) } else { None },
            if p[4] != 0 { Some(p[5]) } else { None },
            p[6],
        );
        println!("{} {}", k, delay(p[0] != 0, p[1], k).to_bits());
    }
}
