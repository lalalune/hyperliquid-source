use node94_bootstrap_window::{selected_window, Selected};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 2, "inputs only");
        let current: u64 = fields[0].parse().unwrap();
        let target: u64 = fields[1].parse().unwrap();
        match selected_window(current, target) {
            Selected::EqualBranch => println!("E"),
            Selected::AheadBranch => println!("A"),
            Selected::Window { first, last } => println!("W\t{first}\t{last}"),
        }
    }
}
