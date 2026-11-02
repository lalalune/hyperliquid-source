extern crate node115_latency_pair;
use node115_latency_pair::{capped_pair, uncapped_pair};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 3);
        let wide: i64 = f[1].parse().unwrap();
        let narrow: i32 = f[2].parse().unwrap();
        match f[0] {
            "0" => println!("{}", uncapped_pair(wide, narrow).to_bits()),
            "1" => {
                let p = capped_pair(wide, narrow);
                println!(
                    "{}\t{}",
                    p.observer_value.to_bits(),
                    p.saved_value.to_bits()
                );
            }
            _ => panic!("invalid lane"),
        }
    }
}
