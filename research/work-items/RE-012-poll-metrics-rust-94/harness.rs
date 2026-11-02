use projection::{apply, pending_poll};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let p: Vec<u64> = line
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(p.len(), 9);
        assert!(p[0] <= 1);
        let result = pending_poll(p[0] == 1, p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        let mut counters = std::array::from_fn(|i| p[8].wrapping_add(i as u64));
        apply(&mut counters, &result);
        let values: Vec<u64> = result
            .increments
            .into_iter()
            .chain([result.last_end])
            .chain(counters)
            .collect();
        println!(
            "{}",
            values
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
}
