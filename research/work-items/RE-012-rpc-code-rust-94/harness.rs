extern crate node94_rpc_code;
use node94_rpc_code::classify;
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let value: u32 = line.unwrap().parse().unwrap();
        let result = classify(value);
        println!("{} {}", result.kind, result.code);
    }
}
