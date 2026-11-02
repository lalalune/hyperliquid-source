//! Selected node94 gossip-reload gates, without clock, file or parser effects.
#![no_std]
#![forbid(unsafe_code)]

/// Compare raw metadata triples: signed first word, unsigned remaining words.
/// This does not assign a calendar type or reproduce the original memory ABI.
pub fn metadata_gate_opens(new: [u32; 3], cached: [u32; 3]) -> bool {
    let normalize = |v: [u32; 3]| (v[0] as i32, v[1], v[2]);
    normalize(new) > normalize(cached)
}

/// Selected throttle gate after normal opaque-helper returns.
/// Quiet-NaN comparisons are unordered; exception/status flags are excluded.
pub fn throttle_gate_opens(previous_first: u32, helper_value: f64, threshold: f64) -> bool {
    previous_first == 0 || helper_value > threshold
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::{metadata_gate_opens, throttle_gate_opens};
    use std::vec::Vec;

    #[test]
    fn target_smoke_rows() {
        for line in include_str!("target-smoke.tsv").lines() {
            let f: Vec<_> = line.split('\t').collect();
            let actual = match f[0] {
                "M" => metadata_gate_opens(
                    [
                        f[1].parse().unwrap(),
                        f[2].parse().unwrap(),
                        f[3].parse().unwrap(),
                    ],
                    [
                        f[4].parse().unwrap(),
                        f[5].parse().unwrap(),
                        f[6].parse().unwrap(),
                    ],
                ),
                "T" => throttle_gate_opens(
                    f[1].parse().unwrap(),
                    f64::from_bits(u64::from_str_radix(f[2], 16).unwrap()),
                    f64::from_bits(u64::from_str_radix(f[3], 16).unwrap()),
                ),
                _ => panic!("unknown frozen operation"),
            };
            let expected: u8 = f.last().unwrap().parse().unwrap();
            assert_eq!(u8::from(actual), expected, "{line}");
        }
    }
}
