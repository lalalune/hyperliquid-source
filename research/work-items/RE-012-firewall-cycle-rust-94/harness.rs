use projection::plan;
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let values: Vec<u64> = line
            .unwrap()
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 5);
        let flags = values[4];
        let result = plan(
            values[0].try_into().unwrap(),
            values[1].try_into().unwrap(),
            f64::from_bits(values[2]),
            f64::from_bits(values[3]),
            [flags & 1 != 0, flags & 2 != 0, flags & 4 != 0],
        );
        println!(
            "{} {} {} {} {}",
            u8::from(result.maybe_update),
            u8::from(result.compute),
            u8::from(result.check),
            u8::from(result.update),
            result.loader_flag
        );
    }
}
