#![no_std]
//! Logical views of node115's two metadata tables and its 16-byte output window.
//! The original table strides/ABI are evidence, not these Rust slice layouts.

const ACCEPT: u16 = 0x1a2;
const REJECT: u16 = 0x6a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    FirstIndexBoundary,
    SecondIndexBoundary,
    Returned,
}

/// Reconstruct ordinary conversion and stop at the two opaque diagnostic PCs.
/// `first` supplies second-table indices; `decimals` supplies bytes at row+0x48.
/// All output bytes other than the observed writes remain caller-owned.
pub fn convert(
    amount: u64,
    index: u64,
    first: &[u64],
    decimals: &[u8],
    out: &mut [u8; 16],
) -> Observation {
    let Some(&secondary) = usize::try_from(index).ok().and_then(|i| first.get(i)) else {
        return Observation::FirstIndexBoundary;
    };
    let Some(&decimal) = usize::try_from(secondary)
        .ok()
        .and_then(|i| decimals.get(i))
    else {
        return Observation::SecondIndexBoundary;
    };
    let tag = if decimal > 8 {
        REJECT
    } else {
        let divisor = 10_u64.pow(u32::from(8 - decimal));
        if !amount.is_multiple_of(divisor) {
            REJECT
        } else {
            out[8..16].copy_from_slice(&(amount / divisor).to_le_bytes());
            ACCEPT
        }
    };
    out[..2].copy_from_slice(&tag.to_le_bytes());
    Observation::Returned
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    include!("../../research/work-items/RE-004-spot-decimal-115/client_fixture.rs");
    #[test]
    fn frozen_original_memory_observations() {
        for line in
            include_str!("../../research/work-items/RE-004-spot-decimal-115/target-smoke.tsv")
                .lines()
        {
            let (input, expected) = line.rsplit_once('\t').unwrap();
            assert_eq!(adapt(input), expected);
        }
    }
    #[test]
    fn bounds_frontiers_preserve_output() {
        let mut out = [0x5a; 16];
        assert_eq!(
            convert(0, 0, &[], &[], &mut out),
            Observation::FirstIndexBoundary
        );
        assert_eq!(out, [0x5a; 16]);
        assert_eq!(
            convert(0, 0, &[0], &[], &mut out),
            Observation::SecondIndexBoundary
        );
        assert_eq!(out, [0x5a; 16]);
    }
}
