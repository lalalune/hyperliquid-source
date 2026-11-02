#![no_std]
#![forbid(unsafe_code)]
/// Full RAX and RDX for node94 [0x555ac00, 0x555ac12).
/// The unsigned threshold alone does not establish an OS errno convention.
#[inline(never)]
pub fn negative_band(input: u64) -> (u64, u64) {
    let eax = (input as u32).wrapping_neg();
    let result = if input <= 0xffff_ffff_ffff_ff88 {
        0
    } else {
        eax as u64
    };
    (result, 0)
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
        assert_eq!(cases, 2928);
    }
}
