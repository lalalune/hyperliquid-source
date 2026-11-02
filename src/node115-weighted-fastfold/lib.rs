//! Conditional two-span weight fold after the opaque first-provider return.
#![no_std]
#![forbid(unsafe_code)]

/// Fold both valid row spans with checked u64 sums, then apply the strict wide gate.
/// This is not a validator-set interpretation, original iterator ABI or consensus API.
pub fn weighted_gate(first_status: u64, basis: u64, first: &[u64], second: &[u64]) -> bool {
    let mut total = 0u64;
    for &weight in first.iter().chain(second.iter()) {
        let Some(next) = total.checked_add(weight) else {
            return false;
        };
        total = next;
    }
    first_status == 1 && (total as u128) * 2 < (basis as u128) * 3
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
            assert_eq!(f.len(), 5);
            let values: Vec<u64> = if f[3] == "-" {
                Vec::new()
            } else {
                f[3].split(',').map(|v| v.parse().unwrap()).collect()
            };
            let split: usize = f[2].parse().unwrap();
            let (first, second) = values.split_at(split);
            assert_eq!(
                weighted_gate(f[0].parse().unwrap(), f[1].parse().unwrap(), first, second),
                f[4] == "1",
                "{row}"
            );
        }
    }
}
