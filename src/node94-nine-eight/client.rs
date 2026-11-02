extern crate node94_leaf;
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let x: Vec<u64> = line
            .unwrap()
            .split(',')
            .map(|v| v.parse().unwrap())
            .collect();
        println!("{}", node94_leaf::nine_eight(x[0], x[1]));
    }
}
