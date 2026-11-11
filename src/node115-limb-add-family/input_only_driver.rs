use node115_limb_add_family::{add_with_carry, guarded_add};
use std::io::{self, BufRead};
mod fixture {
    include!("../../research/work-items/RE-004-limb-add-family-115/client_fixture.rs");
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input line");
        let v: Vec<u64> = line
            .split_whitespace()
            .map(|s| s.parse().expect("raw u64"))
            .collect();
        assert_eq!(v.len(), 10);
        println!(
            "{}",
            fixture::observe(
                v[0] as usize,
                v[1] as usize,
                [v[2], v[3], v[4], v[5]],
                [v[6], v[7], v[8], v[9]]
            )
        );
    }
}
