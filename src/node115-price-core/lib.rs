//! Node115 post-round-helper scalar projection.
//! Reuses MIT policy at5491d673, with fresh115 evidence in RE-014-price-core-115.
//! No clock, auction lifecycle, original memory/result ABI or FP-status claim.
#![no_std]
#![forbid(unsafe_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartBelowFloor;

fn saturated_elapsed(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value >= 18446744073709551616.0 {
        u64::MAX
    } else {
        value as u64
    }
}

/// Calculate the captured arithmetic suffix given the already-rounded helper word.
/// The raw word does not imply original helper reachability or a wall-clock unit API.
pub fn quote_from_rounded_word(
    rounded_bits: u64,
    bucket: u64,
    start: u64,
    floor: u64,
) -> Result<u64, StartBelowFloor> {
    if start < floor {
        return Err(StartBelowFloor);
    }
    let elapsed = saturated_elapsed(f64::from_bits(rounded_bits));
    let raw_factor = 1.0 - elapsed as f64 / bucket as f64;
    let factor = if raw_factor > 0.0 { raw_factor } else { 0.0 };
    let span = (start - floor) as f64;
    let product = saturated_elapsed(factor * span);
    Ok(product.checked_add(floor).unwrap_or(floor))
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    #[test]
    fn frozen_target_rows() {
        for row in
            include_str!("../../research/work-items/RE-014-price-core-115/target-smoke.tsv").lines()
        {
            let f: Vec<_> = row.split('\t').collect();
            let result = quote_from_rounded_word(
                f[0].parse().unwrap(),
                f[1].parse().unwrap(),
                f[2].parse().unwrap(),
                f[3].parse().unwrap(),
            );
            match result {
                Ok(value) => {
                    assert_eq!(f.len(), 6);
                    assert_eq!(f[4], "O", "{row}");
                    assert_eq!(value, f[5].parse::<u64>().unwrap(), "{row}");
                }
                Err(_) => {
                    assert_eq!(f.len(), 5);
                    assert_eq!(f[4], "E", "{row}");
                }
            }
        }
    }
}
