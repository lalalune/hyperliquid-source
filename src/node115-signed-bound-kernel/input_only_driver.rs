use node115_signed_bound_kernel::{observe, Observation, Row};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let v: Vec<u64> = line
            .split_whitespace()
            .map(|x| x.parse().expect("raw u64"))
            .collect();
        assert_eq!(v.len(), 6);
        let row = Row {
            multiplier: v[0],
            a: v[1],
            b: v[2],
            c: v[3],
            d: v[4],
            signed: v[5] as i64,
        };
        match observe(row) {
            Observation::Word(n) => println!("C:{n}"),
            Observation::DiagnosticBoundary => println!("N"),
        }
    }
}
