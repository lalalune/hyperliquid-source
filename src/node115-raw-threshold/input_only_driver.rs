use node115_raw_threshold::{after_secondary_diagnostic, after_sum_diagnostic, enter, Observation};
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let v: Vec<u64> = line
            .split_whitespace()
            .map(|s| s.parse().expect("raw u64"))
            .collect();
        assert_eq!(v.len(), 6);
        let observed = match v[0] {
            0 => enter(v[1], v[2], v[3], v[4], v[5]),
            1 => after_sum_diagnostic(v[1], v[2], v[3], v[4], v[5]),
            2 => {
                assert_eq!(&v[2..5], &[0, 0, 0]);
                after_secondary_diagnostic(v[1], v[5])
            }
            _ => panic!("qualified phase"),
        };
        match observed {
            Observation::SumDiagnosticBoundary => println!("A"),
            Observation::SecondaryDiagnosticBoundary => println!("B"),
            Observation::Values(x) => println!("V:{}:{}:{}", x.quotient, x.threshold, x.raw_head),
        }
    }
}
