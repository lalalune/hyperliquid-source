use node115_bootstrap_range::{plan, Plan};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 2, "input words only");
        match plan(f[0].parse().unwrap(), f[1].parse().unwrap()) {
            Plan::SpanExit => println!("S"),
            Plan::ReversedContinuation => println!("R"),
            Plan::Window { first, last } => println!("W\t{first}\t{last}"),
        }
    }
}
