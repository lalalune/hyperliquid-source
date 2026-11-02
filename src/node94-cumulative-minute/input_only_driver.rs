extern crate node94_cumulative_minute;
use node94_cumulative_minute::{classify_raw_word, LocalMinute};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        match classify_raw_word(line.unwrap().parse().unwrap()) {
            LocalMinute::Accepted(value) => println!("V\t{value}"),
            LocalMinute::NarrowingExit => println!("N"),
            LocalMinute::AssertionExit => println!("A"),
        }
    }
}
