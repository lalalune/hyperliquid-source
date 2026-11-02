//! Raw signed-pair numeric projections, not a clock or metrics/storage API.
#![no_std]
#![forbid(unsafe_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PairProjection {
    pub observer_value: f64,
    /// Pre-observer-call slot; subsequent record use requires its preservation.
    pub saved_value: f64,
}
fn pair_value(mut wide: i64, mut narrow: i32) -> f64 {
    if wide < 0 && narrow > 0 {
        wide += 1;
        narrow -= 1_000_000_000;
    }
    let value = wide as f64 + narrow as f64 / 1_000_000_000.0;
    if value > 0.0 {
        value
    } else {
        0.0
    }
}
pub fn uncapped_pair(wide: i64, narrow: i32) -> f64 {
    pair_value(wide, narrow)
}
pub fn capped_pair(wide: i64, narrow: i32) -> PairProjection {
    let value = pair_value(wide, narrow);
    PairProjection {
        observer_value: value.min(60.0),
        saved_value: value,
    }
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    #[test]
    fn frozen_native_rows() {
        for row in include_str!("target-smoke.tsv").lines() {
            let f: Vec<_> = row.split('\t').collect();
            let wide: i64 = f[1].parse().unwrap();
            let narrow: i32 = f[2].parse().unwrap();
            if f[0] == "0" {
                assert_eq!(f.len(), 4);
                assert_eq!(
                    uncapped_pair(wide, narrow).to_bits(),
                    f[3].parse::<u64>().unwrap(),
                    "{row}"
                );
            } else {
                assert_eq!(f[0], "1");
                assert_eq!(f.len(), 5);
                let p = capped_pair(wide, narrow);
                assert_eq!(
                    p.observer_value.to_bits(),
                    f[3].parse::<u64>().unwrap(),
                    "{row}"
                );
                assert_eq!(
                    p.saved_value.to_bits(),
                    f[4].parse::<u64>().unwrap(),
                    "{row}"
                );
            }
        }
    }
}
