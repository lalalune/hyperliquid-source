#![no_std]
#![forbid(unsafe_code)]
/// Full RAX value for node94 [0x521cc40, 0x521cc5d).
#[inline(never)]
pub fn pointer_sum(a: u64, b: u64) -> u64 {
    let sum = a.wrapping_add(b);
    if a == 0 || b == 0 {
        sum
    } else {
        sum.wrapping_sub(12)
    }
}

#[cfg(test)]
extern crate self as node94_leaf;
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod client_support;
#[cfg(test)]
mod tests {
    use super::client_support;
    use std::vec::Vec;
    #[test]
    fn frozen_pre_rust_observations() {
        let mut cases = 0;
        for row in include_str!("vectors.tsv").lines() {
            let columns: Vec<_> = row.split('\t').collect();
            let input: Vec<u64> = columns[1].split(',').map(|s| s.parse().unwrap()).collect();
            let expected: Vec<u64> = columns[2].split(',').map(|s| s.parse().unwrap()).collect();
            assert_eq!(
                client_support::evaluate(&input),
                expected,
                "case {}",
                columns[0]
            );
            cases += 1;
        }
        assert_eq!(cases, 2656);
    }
}
