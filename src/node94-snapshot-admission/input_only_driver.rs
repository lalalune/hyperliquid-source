use node94_snapshot_admission::{selected_admission, Selected};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 4, "inputs only");
        let lane: u8 = f[0].parse().unwrap();
        assert!(lane < 3);
        match selected_admission(
            f[1].parse().unwrap(),
            f[2].parse().unwrap(),
            f[3].parse().unwrap(),
        ) {
            Selected::PastFreezeAssertion => println!("X"),
            Selected::Freeze => println!("F"),
            Selected::Periodic => println!("P"),
            Selected::Skip => println!("S"),
        }
    }
}
