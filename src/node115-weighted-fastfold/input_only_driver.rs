extern crate node115_weighted_fastfold;
use node115_weighted_fastfold::weighted_gate;
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 4);
        let values: Vec<u64> = if f[3] == "-" {
            Vec::new()
        } else {
            f[3].split(',').map(|v| v.parse().unwrap()).collect()
        };
        let split: usize = f[2].parse().unwrap();
        let (first, second) = values.split_at(split);
        println!(
            "{}",
            u8::from(weighted_gate(
                f[0].parse().unwrap(),
                f[1].parse().unwrap(),
                first,
                second
            ))
        );
    }
}
