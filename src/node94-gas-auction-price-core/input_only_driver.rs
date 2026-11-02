extern crate node94_gas_auction_price_core;
use node94_gas_auction_price_core::quote_from_rounded_word;
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 4);
        match quote_from_rounded_word(
            f[0].parse().unwrap(),
            f[1].parse().unwrap(),
            f[2].parse().unwrap(),
            f[3].parse().unwrap(),
        ) {
            Ok(value) => println!("O\t{value}"),
            Err(_) => println!("E\t11936128518282651045"),
        }
    }
}
